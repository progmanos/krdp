// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "HandoverManager.h"
#include "NotificationUtil.h"

#include <chrono>
#include <filesystem>

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QFile>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QUuid>

#include <KLocalizedString>
#include <KUser>

#include <HandoverClient.h>

using namespace Qt::StringLiterals;
using namespace std::chrono_literals;

namespace
{
// Poll StartHandover for up to 60s (60 * 1s) so slow session startups can still
// register with krdp-dispatcher after KWin and D-Bus finish initializing.
constexpr int kMaxHandoverRetries = 60;
constexpr auto kHandoverRetryInterval = 1s;

constexpr auto kKdeShutdownService = "org.kde.Shutdown"_L1;
constexpr auto kKdeShutdownPath = "/Shutdown"_L1;
constexpr auto kKdeShutdownInterface = "org.kde.Shutdown"_L1;
constexpr auto kKdeShutdownLogoutMethod = "logout"_L1;
// Bounded synchronous wait for org.kde.Shutdown.logout before falling back to
// stopping graphical-session.target directly if ksmserver/plasma-shutdown hangs.
constexpr auto kKdeShutdownTimeout = 5s;

constexpr auto kSystemdService = "org.freedesktop.systemd1"_L1;
constexpr auto kSystemdPath = "/org/freedesktop/systemd1"_L1;
constexpr auto kSystemdManagerInterface = "org.freedesktop.systemd1.Manager"_L1;
constexpr auto kSystemdStopUnitMethod = "StopUnit"_L1;
constexpr auto kGraphicalSessionTarget = "graphical-session.target"_L1;
constexpr auto kSystemdReplaceMode = "replace"_L1;

constexpr auto kCertificateFileName = "server.crt"_L1;
constexpr auto kCertificateKeyFileName = "server.key"_L1;
constexpr auto kRuntimeSubdirName = "krdp"_L1;
constexpr auto kCertificateDirTemplate = "cert-XXXXXX"_L1;
constexpr auto kFallbackHandoverUserName = "krdp"_L1;

QString sessionUsername()
{
    const QString loginName = KUser().loginName();
    return loginName.isEmpty() ? kFallbackHandoverUserName.toString() : loginName;
}

QString generatePassword()
{
    // A 128-bit RFC 4122 v4 UUID formatted as 32 lowercase hexadecimal digits.
    // Provides 128 bits of cryptographic entropy, perfectly saturating FreeRDP's
    // 128-bit NTLM NTOWFv1A digest while containing only [0-9a-f] characters
    // that are safe from SAM delimiter issues.
    return QUuid::createUuid().toString(QUuid::Id128);
}
}

HandoverManager::HandoverManager(const QString &remoteId, KRdp::Server *server, bool terminateOnDisconnect, QObject *parent)
    : QObject(parent)
    , m_remoteId(remoteId)
    , m_server(server)
    , m_terminateOnDisconnect(terminateOnDisconnect)
{
    m_handover = std::make_unique<KRdp::HandoverClient>(this);

    connect(m_handover.get(), &KRdp::HandoverClient::handoverRequested, this, [this](const QString &newRemoteId) {
        qDebug() << "Handover requested for new remote id:" << newRemoteId << "(previous:" << m_remoteId << ")";
        m_remoteId = newRemoteId;
        m_handoverAttempts = 0;
        start();
    });
    connect(m_handover.get(), &KRdp::HandoverClient::takeClientReady, this, &HandoverManager::onTakeClientReady);
    connect(m_handover.get(), &KRdp::HandoverClient::redirectClient, this, &HandoverManager::onRedirectClient);
    connect(m_handover.get(), &KRdp::HandoverClient::clientDisconnected, this, [this](const QString &remoteId) {
        if (remoteId == m_remoteId) {
            qDebug() << "Remote client" << remoteId << "disconnected from dispatcher";
            logoutSession();
            QCoreApplication::quit();
        }
    });
    connect(m_server, &KRdp::Server::newConnectionCreated, this, [this](KRdp::RdpConnection *connection) {
        const bool isTakeover = (m_currentConnection && m_currentConnection != connection);
        if (isTakeover) {
            qDebug() << "Replacing existing RDP client connection with new handover connection";
            disconnect(m_currentConnection, nullptr, this, nullptr);
            m_currentConnection->close(KRdp::RdpConnection::CloseReason::ReplacedByOtherConnection);
        }
        m_currentConnection = connection;
        // newConnectionCreated is emitted before RdpConnection::initialize()
        // (queued) builds the SAM file and before onPostConnect() verifies the
        // credentials, so the one-time password can only be discarded once the
        // client has authenticated and reached the Activated state.
        connect(connection, &KRdp::RdpConnection::stateChanged, this, [this, connection](KRdp::RdpConnection::State state) {
            if (connection == m_currentConnection && state == KRdp::RdpConnection::State::Activated) {
                clearOneTimeCredentials();
            }
        });
        qDebug() << "Handover session adopted a new RDP client";
        if (isTakeover) {
            connect(connection, &KRdp::RdpConnection::stateChanged, this, [connection](KRdp::RdpConnection::State state) {
                if (state == KRdp::RdpConnection::State::Streaming) {
                    const QString addr = connection->clientAddress();
                    const QString body = addr.isEmpty() ? i18n("Your desktop session was transferred to a new remote connection.")
                                                        : i18n("Your desktop session was transferred to a new remote connection (%1).", addr);
                    KRdpServer::NotificationUtil::sendNotification(i18n("Session Transferred"), body);
                }
            });
        }
        connect(connection, &KRdp::RdpConnection::stateChanged, this, [this, connection](KRdp::RdpConnection::State state) {
            if (connection == m_currentConnection && state == KRdp::RdpConnection::State::Closed) {
                qDebug() << "Handover RDP connection closed";
                logoutSession();
                QCoreApplication::quit();
            }
        });
    });
}

HandoverManager::~HandoverManager()
{
    if (m_currentConnection) {
        disconnect(m_currentConnection, nullptr, this, nullptr);
        m_currentConnection->close(KRdp::RdpConnection::CloseReason::ReplacedByOtherConnection);
    }
}

void HandoverManager::logoutSession()
{
    if (!m_terminateOnDisconnect) {
        return;
    }
    m_terminateOnDisconnect = false;

    qDebug() << "Logging out of user graphical session on disconnect";
    auto shutdownMsg = QDBusMessage::createMethodCall(kKdeShutdownService.toString(),
                                                      kKdeShutdownPath.toString(),
                                                      kKdeShutdownInterface.toString(),
                                                      kKdeShutdownLogoutMethod.toString());
    QDBusConnection::sessionBus().call(shutdownMsg, QDBus::Block, std::chrono::milliseconds(kKdeShutdownTimeout).count());

    auto systemdMsg = QDBusMessage::createMethodCall(kSystemdService.toString(),
                                                     kSystemdPath.toString(),
                                                     kSystemdManagerInterface.toString(),
                                                     kSystemdStopUnitMethod.toString());
    systemdMsg << kGraphicalSessionTarget.toString() << kSystemdReplaceMode.toString();
    QDBusConnection::sessionBus().call(systemdMsg, QDBus::NoBlock);
}

void HandoverManager::clearOneTimeCredentials()
{
    if (m_oneTimeUser.password.isEmpty()) {
        return;
    }
    m_oneTimeUser.password.fill(u'\0');
    m_oneTimeUser = {};
    m_server->setUsers({});
    qDebug() << "Discarded one-time handover credentials after authentication";
}

void HandoverManager::start()
{
    if (!m_handover->isAvailable()) {
        qWarning() << "KRdp Dispatcher is not available on the D-Bus, cannot start handover";
        return;
    }

    qDebug() << "Starting handover for remote id:" << m_remoteId;

    // Use the actual session username with an ephemeral one-time password for
    // the NLA ServerRedirection handshake, checked against this session's SAM
    // database.
    m_oneTimeUser.name = sessionUsername();
    m_oneTimeUser.password = generatePassword();

    requestHandover();
}

void HandoverManager::requestHandover()
{
    m_handover->startHandover(m_remoteId, m_oneTimeUser.name, m_oneTimeUser.password, [this](bool success, const KRdp::HandoverClient::HandoverResult &result) {
        if (!success) {
            // The client may not be connected to the dispatcher yet; retry.
            if (++m_handoverAttempts < kMaxHandoverRetries) {
                QTimer::singleShot(kHandoverRetryInterval, this, [this]() {
                    requestHandover();
                });
            } else {
                qWarning() << "Gave up starting the handover for remote id:" << m_remoteId;
                logoutSession();
                QCoreApplication::quit();
            }
            return;
        }

        applyCertificate(result.certificate, result.certificateKey);
        m_server->setUsers({m_oneTimeUser});
        if (!m_server->initialize()) {
            qWarning() << "Failed to initialize the handover server";
        }
    });
}

void HandoverManager::applyCertificate(const QString &certificate, const QString &key)
{
    if (!m_certificateDir) {
        const auto runtimeLocation = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
        const std::filesystem::path runtimeDir = std::filesystem::path(runtimeLocation.toStdString()) / kRuntimeSubdirName.toString().toStdString();
        std::error_code ec;
        std::filesystem::create_directories(runtimeDir, ec);
        std::filesystem::permissions(runtimeDir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);

        const QString templatePath = QString::fromStdString((runtimeDir / kCertificateDirTemplate.toString().toStdString()).string());
        m_certificateDir = std::make_unique<QTemporaryDir>(templatePath);
        m_certificatePath = m_certificateDir->filePath(kCertificateFileName.toString());
        m_certificateKeyPath = m_certificateDir->filePath(kCertificateKeyFileName.toString());
    }

    QFile certificateFile(m_certificatePath);
    QFile keyFile(m_certificateKeyPath);
    if (!certificateFile.open(QIODevice::WriteOnly | QIODevice::Truncate) || !keyFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "Unable to write the certificate for the handover";
        return;
    }
    certificateFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    keyFile.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    certificateFile.write(certificate.toLatin1());
    keyFile.write(key.toLatin1());
    certificateFile.close();
    keyFile.close();

    m_server->setTlsCertificate(std::filesystem::path(m_certificatePath.toStdString()));
    m_server->setTlsCertificateKey(std::filesystem::path(m_certificateKeyPath.toStdString()));

    qDebug() << "Applied the handover certificate";
}

void HandoverManager::onTakeClientReady(const QString &remoteId)
{
    if (remoteId != m_remoteId) {
        qWarning() << "Unexpected remote id in TakeClientReady:" << remoteId;
        return;
    }

    m_handover->takeClient(remoteId, [this](bool success, int fd) {
        if (!success || fd < 0) {
            qWarning() << "Failed to take over the client socket";
            return;
        }

        // The RDP connection takes ownership of the descriptor.
        m_server->adoptConnection(fd);
    });
}

void HandoverManager::onRedirectClient(const QString &remoteId, const QString &username, const QString &password)
{
    if (remoteId != m_remoteId) {
        qWarning() << "Unexpected remote id in RedirectClient:" << remoteId;
        return;
    }

    if (!m_currentConnection) {
        qWarning() << "Cannot redirect client, no active RDP connection";
        return;
    }

    KRdp::RedirectionInfo info;
    info.routingToken = remoteId;
    info.username = username;
    info.password = password;
    m_terminateOnDisconnect = false;
    m_currentConnection->sendServerRedirection(info);
}

#include "moc_HandoverManager.cpp"
