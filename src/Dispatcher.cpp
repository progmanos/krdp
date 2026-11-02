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

#include <freerdp/freerdp.h>
#include <winpr/ssl.h>

#include "Redirection.h"

#include "krdp_logging.h"
#include "org_kde_krdp_dispatcher_adaptor.h"

using namespace Qt::StringLiterals;

namespace
{
constexpr auto kDBusService = "org.kde.krdp.Dispatcher";
constexpr auto kDBusObjectPath = "/org/kde/krdp/Dispatcher";
constexpr auto kDBusInterface = "org.kde.krdp.Dispatcher";
constexpr auto kPeekTimeout = std::chrono::milliseconds(2000);
constexpr auto kTakeClientTimeout = std::chrono::seconds(30);
constexpr size_t kPeekBufferSize = 256;
constexpr size_t kTpktHeaderSize = 4;
constexpr uint8_t kTpktVersion3 = 3;
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

    if (!connection.registerService(QString::fromLatin1(kDBusService))) {
        qCCritical(KRDP) << "Could not register D-Bus service" << kDBusService;
        return false;
    }

    if (!connection.registerObject(QString::fromLatin1(kDBusObjectPath), this)) {
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
        connection.unregisterObject(QString::fromLatin1(kDBusObjectPath));
        connection.unregisterService(QString::fromLatin1(kDBusService));
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
        qCDebug(KRDP) << "First bytes of incoming connection:" << QString::fromLatin1(data.left(32));
    }
    const QByteArrayView view(data);

    // A redirected client presents the routing token after a "Cookie: msts="
    // prefix in its X.224 Connection Request.
    constexpr QByteArrayView tokenPrefix("Cookie: msts=");
    const auto tokenPos = view.indexOf(tokenPrefix);
    if (tokenPos >= 0) {
        const auto valueStart = tokenPos + tokenPrefix.size();
        const auto crlf = view.indexOf("\r\n", valueStart);
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
    constexpr auto plainPrefix = "Cookie: mstshash=";
    if (view.indexOf(plainPrefix) >= 0) {
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
        const auto tpktLength = static_cast<qsizetype>((static_cast<uint8_t>(buffer[2]) << 8) | static_cast<uint8_t>(buffer[3]));
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
        sendErrorReply(QDBusError::UnknownObject, QStringLiteral("Unknown remote id %1").arg(remoteId));
        return {};
    }

    if (!client->connection && client->ownerName.isEmpty() && client->pendingSocket == -1) {
        sendErrorReply(QDBusError::Disconnected, QStringLiteral("Remote client %1 has disconnected").arg(remoteId));
        return {};
    }

    const auto callerService = message().service();
    const auto callerUid = d->callerUid(callerService);

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
            sendErrorReply(QDBusError::Failed, QStringLiteral("No session currently owns remote client %1").arg(remoteId));
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
        sendErrorReply(QDBusError::Failed, QStringLiteral("Unable to read system certificate or key"));
        return {};
    }

    certificateKey = QString::fromLatin1(keyFile.readAll());
    return QString::fromLatin1(certificateFile.readAll());
}

QDBusUnixFileDescriptor Dispatcher::TakeClient(const QString &remoteId)
{
    auto *client = d->findClient(remoteId);
    if (!client) {
        sendErrorReply(QDBusError::UnknownObject, QStringLiteral("Unknown remote id %1").arg(remoteId));
        return {};
    }

    if (client->dstName != message().service()) {
        sendErrorReply(QDBusError::AccessDenied, QStringLiteral("Caller is not authorized to take over remote id %1").arg(remoteId));
        return {};
    }

    if (client->dstUid != d->callerUid(message().service())) {
        sendErrorReply(QDBusError::AccessDenied, QStringLiteral("Caller is not authorized to take over remote id %1").arg(remoteId));
        return {};
    }

    if (client->pendingSocket == -1) {
        sendErrorReply(QDBusError::Failed, QStringLiteral("Remote client %1 has not reconnected yet").arg(remoteId));
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

void Dispatcher::emitTakeClientReady(const QString &remoteId)
{
    auto *client = d->findClient(remoteId);
    if (!client || client->dstName.isEmpty()) {
        return;
    }

    QDBusMessage message = QDBusMessage::createTargetedSignal(client->dstName,
                                                              QString::fromLatin1(kDBusObjectPath),
                                                              QString::fromLatin1(kDBusInterface),
                                                              QStringLiteral("TakeClientReady"));
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitRedirectClient(const QString &destination, const QString &remoteId, const QString &username, const QString &password)
{
    QDBusMessage message = QDBusMessage::createTargetedSignal(destination,
                                                              QString::fromLatin1(kDBusObjectPath),
                                                              QString::fromLatin1(kDBusInterface),
                                                              QStringLiteral("RedirectClient"));
    message.setArguments({remoteId, username, password});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitClientConnected(const QString &remoteId)
{
    QDBusMessage message =
        QDBusMessage::createSignal(QString::fromLatin1(kDBusObjectPath), QString::fromLatin1(kDBusInterface), QStringLiteral("ClientConnected"));
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

void Dispatcher::emitClientDisconnected(const QString &remoteId)
{
    QDBusMessage message =
        QDBusMessage::createSignal(QString::fromLatin1(kDBusObjectPath), QString::fromLatin1(kDBusInterface), QStringLiteral("ClientDisconnected"));
    message.setArguments({remoteId});
    QDBusConnection::systemBus().send(message);
}

rdp_settings *Dispatcher::rdpSettings() const
{
    return d->settings;
}

} // namespace KRdp

#include "moc_Dispatcher.cpp"