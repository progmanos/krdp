// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "Dispatcher.h"
#include "DispatcherConnection.h"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDBusMessage>
#include <QDBusServiceWatcher>
#include <QFile>
#include <QPointer>
#include <QRandomGenerator>
#include <QSocketNotifier>
#include <QTimer>

#include <KUser>

#include <freerdp/freerdp.h>
#include <winpr/ssl.h>

#include "Redirection.h"

#include "krdp_logging.h"
#include "org_kde_krdp_dispatcher_adaptor.h"

using namespace Qt::StringLiterals;

namespace
{
constexpr auto kDBusService = "org.kde.krdp.Dispatcher"_L1;
constexpr auto kDBusObjectPath = "/org/kde/krdp/Dispatcher"_L1;
constexpr auto kDBusInterface = "org.kde.krdp.Dispatcher"_L1;
constexpr auto kSignalHandoverRequested = "HandoverRequested"_L1;
constexpr auto kSignalTakeClientReady = "TakeClientReady"_L1;
constexpr auto kSignalRedirectClient = "RedirectClient"_L1;
constexpr auto kSignalClientConnected = "ClientConnected"_L1;
constexpr auto kSignalClientDisconnected = "ClientDisconnected"_L1;

constexpr auto kErrUnknownRemoteId = "Unknown remote id %1"_L1;
constexpr auto kErrClientDisconnected = "Remote client %1 has disconnected"_L1;
constexpr auto kErrCallerUidUndetermined = "Unable to determine caller UID for remote id %1"_L1;
constexpr auto kErrCallerUidNotAuthorized = "Caller UID %1 is not authorized to claim remote id %2"_L1;
constexpr auto kErrOnlyGreeterMayClaim = "Only the display manager greeter may claim unauthenticated remote id %1"_L1;
constexpr auto kErrNoSessionOwnsClient = "No session currently owns remote client %1"_L1;
constexpr auto kErrUnableToReadCertOrKey = "Unable to read system certificate or key"_L1;
constexpr auto kErrCallerNotAuthorized = "Caller is not authorized to take over remote id %1"_L1;
constexpr auto kErrClientNotReconnected = "Remote client %1 has not reconnected yet"_L1;
constexpr auto kErrOnlyRootMayAuthorize = "Only root may authorize handover for remote id %1"_L1;
constexpr auto kErrUnknownUser = "Unknown user %1"_L1;
constexpr auto kErrOnlyRootMayTransfer = "Only root may transfer handover from %1 to %2"_L1;
constexpr auto kErrUnknownOldRemoteId = "Unknown old remote id %1"_L1;
constexpr auto kErrUnknownNewRemoteId = "Unknown new remote id %1"_L1;

// Maximum time to wait for the initial X.224 Connection Request PDU after TCP
// accept() before treating a partial/silent socket as a new client.
constexpr auto kPeekTimeout = std::chrono::milliseconds(2000);
// Maximum time between StartHandover (sending ServerRedirection) and the
// target session calling TakeClient after the redirected client reconnects.
constexpr auto kTakeClientTimeout = std::chrono::seconds(30);
// An X.224 Connection Request PDU with an RDP routing token or mstshash cookie
// is typically 40-120 bytes; 256 bytes comfortably captures the cookie header.
constexpr size_t kPeekBufferSize = 256;
constexpr qsizetype kDebugPeekPreviewLength = 32;

// ITU-T Rec. T.123 / RFC 1006 Section 6 & [MS-RDPBCGR] 2.2.1.1 TPKT header:
// 4 bytes: [version = 3, reserved = 0, length_hi (byte 2), length_lo (byte 3)].
constexpr size_t kTpktHeaderSize = 4;
constexpr size_t kTpktLengthHighByteIndex = 2;
constexpr size_t kTpktLengthLowByteIndex = 3;
constexpr int kBitsPerByte = 8;
constexpr uint8_t kTpktVersion3 = 3;

constexpr QByteArrayView kRoutingTokenPrefix = "Cookie: msts=";
constexpr QByteArrayView kPlainCookiePrefix = "Cookie: mstshash=";
constexpr QByteArrayView kCookieTerminator = "\r\n";

constexpr uint kRootUid = 0;
constexpr auto kGreeterUserName = "plasmalogin"_L1;
}

namespace KRdp
{

class KRDP_NO_EXPORT Dispatcher::Private
{
public:
    QHostAddress address = QHostAddress::LocalHost;
    quint16 port = 3389;

    std::filesystem::path systemCertificate;
    std::filesystem::path systemCertificateKey;

    rdp_settings *settings = nullptr;

    // Watches a freshly accepted socket until its routing token (or absence
    // thereof) can be determined by peeking at the initial bytes.
    struct PendingPeek {
        QSocketNotifier *notifier = nullptr;
        QTimer *timeoutTimer = nullptr;
    };

    struct RemoteClient {
        QString remoteId;

        // The initial connection, as long as the client is still held by the
        // dispatcher, i.e. before the first handover.
        QPointer<DispatcherConnection> connection;

        // Unique bus name of the session that currently owns the client.
        QString ownerName;
        // Unique bus name of the session that wants to take over next.
        QString dstName;
        // UID of the session that called StartHandover, used to verify the
        // subsequent TakeClient call.
        uint dstUid = 0;
        // UID authorized by the display manager (via AuthorizeHandover or
        // TransferHandover) to claim this remoteId for a user session.
        // UINT32_MAX indicates the client has not yet authenticated a user
        // session (only the display manager greeter or root may claim it).
        uint authorizedUid = UINT32_MAX;

        // Socket of a reconnected (redirected) client, waiting to be
        // transferred via TakeClient().
        qintptr pendingSocket = -1;
        QPointer<QSocketNotifier> pendingNotifier;

        // Aborts the handover when nothing happened for too long.
        QTimer *abortTimer = nullptr;
    };

    QHash<QString, RemoteClient *> remoteClients;
    QHash<qintptr, PendingPeek> pendingPeeks;
    QDBusServiceWatcher *serviceWatcher = nullptr;

    RemoteClient *findClient(const QString &remoteId) const
    {
        return remoteClients.value(remoteId);
    }

    // Look up the UID of the process that owns the given D-Bus connection.
    // Returns UINT32_MAX if it cannot be determined.
    uint callerUid(const QString &service) const
    {
        const auto reply = QDBusConnection::systemBus().interface()->serviceUid(service);
        if (!reply.isValid()) {
            return UINT32_MAX;
        }
        return reply.value();
    }

    uint greeterUid() const
    {
        const KUser greeterUser(kGreeterUserName.toString());
        return greeterUser.isValid() ? static_cast<uint>(greeterUser.userId().nativeId()) : UINT32_MAX;
    }

    void removeClient(RemoteClient *client)
    {
        if (serviceWatcher) {
            if (!client->ownerName.isEmpty()) {
                serviceWatcher->removeWatchedService(client->ownerName);
            }
            if (!client->dstName.isEmpty()) {
                serviceWatcher->removeWatchedService(client->dstName);
            }
        }
        if (client->pendingNotifier) {
            delete client->pendingNotifier;
            client->pendingNotifier = nullptr;
        }
        if (client->abortTimer) {
            client->abortTimer->stop();
            delete client->abortTimer;
        }
        remoteClients.remove(client->remoteId);
        delete client;
    }
};

Dispatcher::Dispatcher(QObject *parent)
    : QTcpServer(parent)
    , d(std::make_unique<Private>())
{
    winpr_InitializeSSL(WINPR_SSL_INIT_DEFAULT);

    d->serviceWatcher = new QDBusServiceWatcher(this);
    d->serviceWatcher->setConnection(QDBusConnection::systemBus());
    d->serviceWatcher->setWatchMode(QDBusServiceWatcher::WatchForUnregistration);
    connect(d->serviceWatcher, &QDBusServiceWatcher::serviceUnregistered, this, [this](const QString &service) {
        d->serviceWatcher->removeWatchedService(service);
        const auto clients = d->remoteClients.values();
        for (auto *client : clients) {
            if (client->ownerName == service) {
                client->ownerName.clear();
            }
            if (client->dstName == service) {
                client->dstName.clear();
                client->dstUid = 0;
            }
            if (!client->connection && client->ownerName.isEmpty() && client->dstName.isEmpty()) {
                const QString remoteId = client->remoteId;
                if (client->pendingSocket != -1) {
                    ::close(client->pendingSocket);
                    client->pendingSocket = -1;
                }
                d->removeClient(client);
                emitClientDisconnected(remoteId);
            }
        }
    });

    // The adaptor exports the org.kde.krdp.Dispatcher interface and forwards
    // the D-Bus method calls to the StartHandover/TakeClient methods below.
    new DispatcherAdaptor(this);
}

Dispatcher::~Dispatcher()
{
    stop();
}

QHostAddress Dispatcher::address() const
{
    return d->address;
}

void Dispatcher::setAddress(const QHostAddress &newAddress)
{
    if (newAddress == d->address) {
        return;
    }

    d->address = newAddress;
}

quint16 Dispatcher::port() const
{
    return d->port;
}

void Dispatcher::setPort(quint16 newPort)
{
    if (newPort == d->port) {
        return;
    }

    d->port = newPort;
}

std::filesystem::path Dispatcher::systemCertificate() const
{
    return d->systemCertificate;
}

void Dispatcher::setSystemCertificate(const std::filesystem::path &path)
{
    d->systemCertificate = path;
}

std::filesystem::path Dispatcher::systemCertificateKey() const
{
    return d->systemCertificateKey;
}

void Dispatcher::setSystemCertificateKey(const std::filesystem::path &path)
{
    d->systemCertificateKey = path;
}

bool Dispatcher::initialize()
{
    if (!std::filesystem::exists(d->systemCertificate) || !std::filesystem::exists(d->systemCertificateKey)) {
        qCCritical(KRDP).nospace() << "A valid TLS certificate (" << QString::fromStdString(d->systemCertificate.filename().string()) << ") and key ("
                                   << QString::fromStdString(d->systemCertificateKey.filename().string()) << ") is required for the dispatcher to run!";
        return false;
    }

    if (!d->settings) {
        // See Server::initialize() for why this is needed.
        d->settings = freerdp_settings_new(FREERDP_SETTINGS_SERVER_MODE);
    }

    return d->settings != nullptr;
}

bool Dispatcher::start()
{
    if (!initialize()) {
        return false;
    }

    auto connection = QDBusConnection::systemBus();
    if (!connection.isConnected()) {
        qCCritical(KRDP) << "Could not connect to the system D-Bus";
        return false;
    }

    if (!connection.registerService(kDBusService.toString())) {
        qCCritical(KRDP) << "Could not register D-Bus service" << kDBusService;
        return false;
    }

    if (!connection.registerObject(kDBusObjectPath.toString(), this)) {
        qCCritical(KRDP) << "Could not register D-Bus object" << kDBusObjectPath;
        return false;
    }

    if (!listen(d->address, d->port)) {
        qCCritical(KRDP) << "Unable to listen for connections on" << d->address << d->port;
        return false;
    }

    qCDebug(KRDP) << "Dispatcher listening for connections on" << serverAddress() << serverPort() << "and D-Bus path" << kDBusObjectPath;
    return true;
}

void Dispatcher::stop()
{
    close();

    if (auto connection = QDBusConnection::systemBus(); connection.isConnected()) {
        connection.unregisterObject(kDBusObjectPath.toString());
        connection.unregisterService(kDBusService.toString());
    }

    for (auto *client : std::as_const(d->remoteClients)) {
        if (client->connection) {
            client->connection->requestStop();
        }
        if (client->pendingSocket != -1) {
            ::close(client->pendingSocket);
        }
    }

    for (auto it = d->pendingPeeks.begin(); it != d->pendingPeeks.end(); ++it) {
        delete it->timeoutTimer;
        delete it->notifier;
        ::close(it.key());
    }
    d->pendingPeeks.clear();
    d->remoteClients.clear();

    if (d->settings) {
        freerdp_settings_free(d->settings);
        d->settings = nullptr;
    }
}

void Dispatcher::incomingConnection(qintptr handle)
{
    Private::PendingPeek peek;
    peek.notifier = new QSocketNotifier(handle, QSocketNotifier::Read, this);
    peek.timeoutTimer = new QTimer(this);
    peek.timeoutTimer->setSingleShot(true);
    peek.timeoutTimer->setInterval(kPeekTimeout);

    connect(peek.notifier, &QSocketNotifier::activated, this, [this, handle]() {
        tryPeek(handle);
    });
    connect(peek.timeoutTimer, &QTimer::timeout, this, [this, handle]() {
        if (d->pendingPeeks.contains(handle)) {
            qCDebug(KRDP) << "Timeout waiting for routing token, treating as new client";
            cleanupPeek(handle);
            handleNewConnection(handle);
        }
    });

    d->pendingPeeks.insert(handle, peek);
    peek.timeoutTimer->start();
}

void Dispatcher::cleanupPeek(qintptr handle)
{
    if (auto it = d->pendingPeeks.find(handle); it != d->pendingPeeks.end()) {
        delete it->timeoutTimer;
        delete it->notifier;
        d->pendingPeeks.erase(it);
    }
}

void Dispatcher::tryPeek(qintptr handle)
{
    if (!d->pendingPeeks.contains(handle)) {
        return;
    }

    char buffer[kPeekBufferSize];
    const auto bytesRead = ::recv(handle, buffer, sizeof(buffer), MSG_PEEK);
    if (bytesRead < 0) {
        if (errno == EAGAIN) {
            return;
        }
        qCDebug(KRDP) << "Error peeking at incoming connection:" << strerror(errno);
        qCWarning(KRDP) << "Closing connection due to peek error";
        cleanupPeek(handle);
        ::close(handle);
        return;
    }
    if (bytesRead == 0) {
        qCDebug(KRDP) << "Connection closed by peer during peek";
        cleanupPeek(handle);
        ::close(handle);
        return;
    }

    qCDebug(KRDP) << "tryPeek received" << bytesRead << "bytes";
    const QByteArray data(buffer, bytesRead);
    if (bytesRead > 0) {
        qCDebug(KRDP) << "First bytes of incoming connection:" << QString::fromLatin1(data.left(kDebugPeekPreviewLength));
    }
    const QByteArrayView view(data);

    // A redirected client presents the routing token after a "Cookie: msts="
    // prefix in its X.224 Connection Request.
    const auto tokenPos = view.indexOf(kRoutingTokenPrefix);
    if (tokenPos >= 0) {
        const auto valueStart = tokenPos + kRoutingTokenPrefix.size();
        const auto crlf = view.indexOf(kCookieTerminator, valueStart);
        if (crlf > valueStart) {
            const auto token = QString::fromLatin1(view.mid(valueStart, crlf - valueStart));
            qCDebug(KRDP) << "Incoming connection with routing token:" << token;
            cleanupPeek(handle);
            handleRedirectedConnection(token, handle);
            return;
        }
    }

    // A plain client presents a "Cookie: mstshash=" in its X.224 Connection
    // Request. If we can already see that, it is definitely a new (non
    // redirected) connection and we do not need to wait for the timeout.
    if (view.indexOf(kPlainCookiePrefix) >= 0) {
        qCDebug(KRDP) << "Incoming connection without routing token";
        cleanupPeek(handle);
        handleNewConnection(handle);
        return;
    }

    // Some RDP clients (such as Remmina when no username is configured) send a
    // bare X.224 Connection Request PDU with no Cookie field at all. Check the
    // 4-byte TPKT header ([MS-RDPBCGR] 2.2.1.1): once the full TPKT packet has
    // arrived without a routing token, treat it immediately as a new client.
    if (bytesRead >= static_cast<ssize_t>(kTpktHeaderSize)) {
        const auto version = static_cast<uint8_t>(buffer[0]);
        const auto tpktLength = static_cast<qsizetype>((static_cast<uint8_t>(buffer[kTpktLengthHighByteIndex]) << kBitsPerByte)
                                                       | static_cast<uint8_t>(buffer[kTpktLengthLowByteIndex]));
        if (version != kTpktVersion3 || bytesRead >= std::min<qsizetype>(tpktLength, sizeof(buffer))) {
            qCDebug(KRDP) << "Complete X.224 Connection Request without routing token, treating as new client";
            cleanupPeek(handle);
            handleNewConnection(handle);
            return;
        }
    }

    // Fewer bytes than the full TPKT packet have arrived so far. Disable the
    // level-triggered read notifier so MSG_PEEK does not spin the event loop
    // while waiting for the timeout.
    if (auto it = d->pendingPeeks.find(handle); it != d->pendingPeeks.end() && it->notifier) {
        it->notifier->setEnabled(false);
    }
    qCDebug(KRDP) << "Partial X.224 Connection Request (" << bytesRead << "bytes), waiting for timeout...";
}

void Dispatcher::handleNewConnection(qintptr handle)
{
    const QString remoteId = QString::number(QRandomGenerator::system()->bounded(1U, UINT32_MAX));

    auto *connection = new DispatcherConnection(this, handle);
    auto *client = new Private::RemoteClient;
    client->remoteId = remoteId;
    client->connection = connection;
    d->remoteClients.insert(remoteId, client);

    qCDebug(KRDP) << "New client, remote id:" << remoteId;

    connect(connection, &DispatcherConnection::closed, this, [this, remoteId, connection]() {
        qCDebug(KRDP) << "Dispatcher connection closed, remote id:" << remoteId;
        if (auto *client = d->findClient(remoteId); client && client->connection == connection) {
            client->connection = nullptr;

            // Nothing is waiting for this client anymore; forget it so its
            // remote id can be reused. When a handover is in progress, the
            // client closes the initial connection to reconnect with the
            // routing token, so do not emit ClientDisconnected yet.
            if (client->ownerName.isEmpty() && client->dstName.isEmpty() && client->pendingSocket == -1) {
                d->removeClient(client);
                emitClientDisconnected(remoteId);
            }
        }
        connection->deleteLater();
    });

    connect(connection, &DispatcherConnection::connected, this, [this, remoteId]() {
        emitClientConnected(remoteId);
    });
}

void Dispatcher::handleRedirectedConnection(const QString &remoteId, qintptr handle)
{
    auto *client = d->findClient(remoteId);
    if (!client || client->dstName.isEmpty()) {
        qCWarning(KRDP) << "Incoming redirected connection with unknown or stale remote id:" << remoteId << ", treating as new client";
        if (client) {
            d->removeClient(client);
            emitClientDisconnected(remoteId);
        }
        handleNewConnection(handle);
        return;
    }

    if (client->pendingSocket != -1) {
        qCWarning(KRDP) << "Remote client" << remoteId << "connected twice, dropping previous socket";
        if (client->pendingNotifier) {
            delete client->pendingNotifier;
            client->pendingNotifier = nullptr;
        }
        ::close(client->pendingSocket);
    }

    client->pendingSocket = handle;
    qCDebug(KRDP) << "Client reconnected, remote id:" << remoteId;

    auto *notifier = new QSocketNotifier(handle, QSocketNotifier::Read, this);
    client->pendingNotifier = notifier;
    connect(notifier, &QSocketNotifier::activated, this, [this, client, remoteId](QSocketDescriptor socket) {
        char buf;
        ssize_t res = ::recv(socket, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
        if (res == 0 || (res < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
            qCWarning(KRDP) << "Pending redirected client" << remoteId << "abruptly disconnected before TakeClient";
            if (client->pendingNotifier) {
                delete client->pendingNotifier;
                client->pendingNotifier = nullptr;
            }
            if (client->pendingSocket != -1) {
                ::close(client->pendingSocket);
                client->pendingSocket = -1;
            }
            if (client->abortTimer) {
                client->abortTimer->stop();
            }
            emitClientDisconnected(remoteId);
            d->removeClient(client);
        }
    });

    emitTakeClientReady(remoteId);
}

QString Dispatcher::StartHandover(const QString &remoteId, const QString &username, const QString &password, QString &certificateKey)
{
    auto *client = d->findClient(remoteId);
    if (!client) {
        sendErrorReply(QDBusError::UnknownObject, kErrUnknownRemoteId.toString().arg(remoteId));
        return {};
    }

    if (!client->connection && client->ownerName.isEmpty() && client->pendingSocket == -1) {
        sendErrorReply(QDBusError::Disconnected, kErrClientDisconnected.toString().arg(remoteId));
        return {};
    }

    const auto callerService = message().service();
    const auto callerUid = d->callerUid(callerService);
    if (callerUid == UINT32_MAX) {
        sendErrorReply(QDBusError::AccessDenied, kErrCallerUidUndetermined.toString().arg(remoteId));
        return {};
    }

    if (client->authorizedUid != UINT32_MAX) {
        if (callerUid != client->authorizedUid && callerUid != kRootUid) {
            sendErrorReply(QDBusError::AccessDenied, kErrCallerUidNotAuthorized.toString().arg(callerUid).arg(remoteId));
            return {};
        }
    } else {
        if (callerUid != kRootUid && callerUid != d->greeterUid()) {
            sendErrorReply(QDBusError::AccessDenied, kErrOnlyGreeterMayClaim.toString().arg(remoteId));
            return {};
        }
    }

    // The connection to the client is still held by the dispatcher: redirect
    // it ourselves.
    if (client->connection) {
        RedirectionInfo redirection;
        redirection.routingToken = remoteId;
        redirection.username = username;
        redirection.password = password;

        client->connection->sendServerRedirection(redirection);
    } else {
        // The client is currently owned by another session: ask that session
        // to redirect it.
        if (client->ownerName.isEmpty()) {
            sendErrorReply(QDBusError::Failed, kErrNoSessionOwnsClient.toString().arg(remoteId));
            return {};
        }

        emitRedirectClient(client->ownerName, remoteId, username, password);
    }

    client->dstName = callerService;
    client->dstUid = callerUid;
    d->serviceWatcher->addWatchedService(callerService);

    if (client->pendingSocket != -1) {
        // The client already reconnected while we were waiting for the
        // destination session.
        emitTakeClientReady(remoteId);
    }

    if (!client->abortTimer) {
        client->abortTimer = new QTimer(this);
        client->abortTimer->setSingleShot(true);
        client->abortTimer->setInterval(kTakeClientTimeout);
        connect(client->abortTimer, &QTimer::timeout, this, [this, client, remoteId]() {
            qCWarning(KRDP) << "Timed out waiting for TakeClient of remote id:" << remoteId;
            if (client->pendingSocket != -1) {
                ::close(client->pendingSocket);
            }
            emitClientDisconnected(remoteId);
            d->removeClient(client);
        });
    }
    client->abortTimer->start();

    QFile certificateFile(QString::fromStdString(d->systemCertificate.string()));
    QFile keyFile(QString::fromStdString(d->systemCertificateKey.string()));
    if (!certificateFile.open(QIODevice::ReadOnly) || !keyFile.open(QIODevice::ReadOnly)) {
        sendErrorReply(QDBusError::Failed, kErrUnableToReadCertOrKey.toString());
        return {};
    }

    certificateKey = QString::fromLatin1(keyFile.readAll());
    return QString::fromLatin1(certificateFile.readAll());
}

QDBusUnixFileDescriptor Dispatcher::TakeClient(const QString &remoteId)
{
    auto *client = d->findClient(remoteId);
    if (!client) {
        sendErrorReply(QDBusError::UnknownObject, kErrUnknownRemoteId.toString().arg(remoteId));
        return {};
    }

    if (client->dstName != message().service()) {
        sendErrorReply(QDBusError::AccessDenied, kErrCallerNotAuthorized.toString().arg(remoteId));
        return {};
    }

    if (client->dstUid != d->callerUid(message().service())) {
        sendErrorReply(QDBusError::AccessDenied, kErrCallerNotAuthorized.toString().arg(remoteId));
        return {};
    }

    if (client->pendingSocket == -1) {
        sendErrorReply(QDBusError::Failed, kErrClientNotReconnected.toString().arg(remoteId));
        return {};
    }

    const auto socket = client->pendingSocket;
    client->pendingSocket = -1;
    if (client->pendingNotifier) {
        delete client->pendingNotifier;
        client->pendingNotifier = nullptr;
    }
    if (!client->ownerName.isEmpty() && client->ownerName != client->dstName) {
        d->serviceWatcher->removeWatchedService(client->ownerName);
    }
    client->ownerName = client->dstName;
    client->dstName.clear();
    client->dstUid = 0;

    if (client->abortTimer) {
        client->abortTimer->stop();
    }

    qCDebug(KRDP) << "Transferring client" << remoteId << "to" << client->ownerName;

    // QDBusUnixFileDescriptor duplicates the file descriptor upon construction
    // via fcntl(F_DUPFD_CLOEXEC). Thus, we can safely close the original socket
    // immediately without deferring to a singleShot timer.
    auto descriptor = QDBusUnixFileDescriptor(socket);
    ::close(socket);

    return descriptor;
}

void Dispatcher::AuthorizeHandover(const QString &remoteId, const QString &username)
{
    if (d->callerUid(message().service()) != kRootUid) {
        sendErrorReply(QDBusError::AccessDenied, kErrOnlyRootMayAuthorize.toString().arg(remoteId));
        return;
    }

    auto *client = d->findClient(remoteId);
    if (!client) {
        sendErrorReply(QDBusError::UnknownObject, kErrUnknownRemoteId.toString().arg(remoteId));
        return;
    }

    const KUser targetUser(username);
    if (!targetUser.isValid()) {
        sendErrorReply(QDBusError::InvalidArgs, kErrUnknownUser.toString().arg(username));
        return;
    }

    client->authorizedUid = static_cast<uint>(targetUser.userId().nativeId());
    qCDebug(KRDP) << "Authorized UID" << client->authorizedUid << "(" << username << ") for handover of remote id:" << remoteId;
}

void Dispatcher::TransferHandover(const QString &oldRemoteId, const QString &newRemoteId)
{
    if (d->callerUid(message().service()) != kRootUid) {
        sendErrorReply(QDBusError::AccessDenied, kErrOnlyRootMayTransfer.toString().arg(oldRemoteId, newRemoteId));
        return;
    }

    if (oldRemoteId == newRemoteId) {
        return;
    }

    auto *oldClient = d->findClient(oldRemoteId);
    if (!oldClient) {
        sendErrorReply(QDBusError::UnknownObject, kErrUnknownOldRemoteId.toString().arg(oldRemoteId));
        return;
    }

    auto *newClient = d->findClient(newRemoteId);
    if (!newClient) {
        sendErrorReply(QDBusError::UnknownObject, kErrUnknownNewRemoteId.toString().arg(newRemoteId));
        return;
    }

    const QString userSessionService = !oldClient->ownerName.isEmpty() ? oldClient->ownerName : oldClient->dstName;
    if (userSessionService.isEmpty()) {
        sendErrorReply(QDBusError::Failed, kErrNoSessionOwnsClient.toString().arg(oldRemoteId));
        return;
    }

    newClient->authorizedUid = (oldClient->authorizedUid != UINT32_MAX) ? oldClient->authorizedUid : d->callerUid(userSessionService);

    qCDebug(KRDP) << "Transferring handover from" << oldRemoteId << "to" << newRemoteId << "for session" << userSessionService
                  << "(authorized UID:" << newClient->authorizedUid << ")";

    // Retire oldClient without emitting ClientDisconnected so the user's
    // active session is not torn down during the transfer.
    if (oldClient->pendingSocket != -1) {
        ::close(oldClient->pendingSocket);
        oldClient->pendingSocket = -1;
    }
    d->removeClient(oldClient);

    d->serviceWatcher->addWatchedService(userSessionService);
    emitHandoverRequested(userSessionService, newRemoteId);
}

void Dispatcher::emitHandoverRequested(const QString &destination, const QString &remoteId)
{
    QDBusMessage message =
        QDBusMessage::createTargetedSignal(destination, kDBusObjectPath.toString(), kDBusInterface.toString(), kSignalHandoverRequested.toString());
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitTakeClientReady(const QString &remoteId)
{
    auto *client = d->findClient(remoteId);
    if (!client || client->dstName.isEmpty()) {
        return;
    }

    QDBusMessage message =
        QDBusMessage::createTargetedSignal(client->dstName, kDBusObjectPath.toString(), kDBusInterface.toString(), kSignalTakeClientReady.toString());
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitRedirectClient(const QString &destination, const QString &remoteId, const QString &username, const QString &password)
{
    QDBusMessage message =
        QDBusMessage::createTargetedSignal(destination, kDBusObjectPath.toString(), kDBusInterface.toString(), kSignalRedirectClient.toString());
    message.setArguments({remoteId, username, password});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitClientConnected(const QString &remoteId)
{
    QDBusMessage message = QDBusMessage::createSignal(kDBusObjectPath.toString(), kDBusInterface.toString(), kSignalClientConnected.toString());
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitClientDisconnected(const QString &remoteId)
{
    QDBusMessage message = QDBusMessage::createSignal(kDBusObjectPath.toString(), kDBusInterface.toString(), kSignalClientDisconnected.toString());
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

rdp_settings *Dispatcher::rdpSettings() const
{
    return d->settings;
}

} // namespace KRdp

#include "moc_Dispatcher.cpp"