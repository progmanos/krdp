// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "HandoverManager.h"

#include <chrono>

#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QFile>
#include <QRandomGenerator>
#include <QTemporaryDir>
#include <QTimer>

#include <HandoverClient.h>

using namespace Qt::StringLiterals;
using namespace std::chrono_literals;

namespace
{
constexpr int kDefaultPasswordLength = 24;
constexpr int kMaxHandoverRetries = 60;
constexpr auto kHandoverRetryInterval = 1s;

QString generateUsername()
{
    return u"krdp-%1"_s.arg(QString::number(QRandomGenerator::system()->bounded(1U, UINT32_MAX), 16));
}

QString generatePassword(int length = kDefaultPasswordLength)
{
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    constexpr qsizetype alphabetSize = sizeof(alphabet) - 1;
    QString password;
    password.reserve(length);
    for (int i = 0; i < length; ++i) {
        password.append(QLatin1Char(alphabet[QRandomGenerator::system()->bounded(alphabetSize)]));
    }
    return password;
}
}

HandoverManager::HandoverManager(const QString &remoteId, KRdp::Server *server, bool terminateOnDisconnect, QObject *parent)
    : QObject(parent)
    , m_remoteId(remoteId)
    , m_server(server)
    , m_terminateOnDisconnect(terminateOnDisconnect)
{
    m_handover = std::make_unique<KRdp::HandoverClient>(this);

    connect(m_handover.get(), &KRdp::HandoverClient::takeClientReady, this, &HandoverManager::onTakeClientReady);
    connect(m_handover.get(), &KRdp::HandoverClient::redirectClient, this, &HandoverManager::onRedirectClient);
    connect(m_handover.get(), &KRdp::HandoverClient::clientDisconnected, this, [this](const QString &remoteId) {
        if (remoteId == m_remoteId) {
            qDebug() << "Remote client" << remoteId << "disconnected from dispatcher";
            if (m_terminateOnDisconnect) {
                qDebug() << "Terminating user graphical session on disconnect";
                auto msg = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.systemd1"),
                                                          QStringLiteral("/org/freedesktop/systemd1"),
                                                          QStringLiteral("org.freedesktop.systemd1.Manager"),
                                                          QStringLiteral("StopUnit"));
                msg << QStringLiteral("graphical-session.target") << QStringLiteral("replace");
                QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
            }
            QCoreApplication::quit();
        }
    });
    connect(m_server, &KRdp::Server::newConnectionCreated, this, [this](KRdp::RdpConnection *connection) {
        m_currentConnection = connection;
        qDebug() << "Handover session adopted a new RDP client";
        connect(connection, &KRdp::RdpConnection::stateChanged, this, [this](KRdp::RdpConnection::State state) {
            if (state == KRdp::RdpConnection::State::Closed) {
                qDebug() << "Handover RDP connection closed";
                if (m_terminateOnDisconnect) {
                    qDebug() << "Terminating user graphical session on disconnect";
                    auto msg = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.systemd1"),
                                                              QStringLiteral("/org/freedesktop/systemd1"),
                                                              QStringLiteral("org.freedesktop.systemd1.Manager"),
                                                              QStringLiteral("StopUnit"));
                    msg << QStringLiteral("graphical-session.target") << QStringLiteral("replace");
                    QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
                }
                QCoreApplication::quit();
            }
        });
    });
}

HandoverManager::~HandoverManager()
{
    if (m_currentConnection) {
        m_currentConnection->close(KRdp::RdpConnection::CloseReason::UserLogoff);
    }
    if (m_terminateOnDisconnect) {
        auto msg = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.systemd1"),
                                                  QStringLiteral("/org/freedesktop/systemd1"),
                                                  QStringLiteral("org.freedesktop.systemd1.Manager"),
                                                  QStringLiteral("StopUnit"));
        msg << QStringLiteral("graphical-session.target") << QStringLiteral("replace");
        QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
    }
}

void HandoverManager::start()
{
    if (!m_handover->isAvailable()) {
        qWarning() << "KRdp Dispatcher is not available on the D-Bus, cannot start handover";
        return;
    }

    qDebug() << "Starting handover for remote id:" << m_remoteId;

    // One-time credentials for the redirected client, checked against the SAM
    // database of this session.
    m_oneTimeUser.name = generateUsername();
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
                if (m_terminateOnDisconnect) {
                    auto msg = QDBusMessage::createMethodCall(QStringLiteral("org.freedesktop.systemd1"),
                                                              QStringLiteral("/org/freedesktop/systemd1"),
                                                              QStringLiteral("org.freedesktop.systemd1.Manager"),
                                                              QStringLiteral("StopUnit"));
                    msg << QStringLiteral("graphical-session.target") << QStringLiteral("replace");
                    QDBusConnection::sessionBus().call(msg, QDBus::NoBlock);
                }
                QCoreApplication::quit();
            }
            return;
        }

        applyCertificate(result.certificate, result.certificateKey);
        m_server->addUser(m_oneTimeUser);
        if (!m_server->initialize()) {
            qWarning() << "Failed to initialize the handover server";
        }
    });
}

void HandoverManager::applyCertificate(const QString &certificate, const QString &key)
{
    if (!m_certificateDir) {
        m_certificateDir = std::make_unique<QTemporaryDir>();
        m_certificatePath = m_certificateDir->filePath(QStringLiteral("server.crt"));
        m_certificateKeyPath = m_certificateDir->filePath(QStringLiteral("server.key"));
    }

    QFile certificateFile(m_certificatePath);
    QFile keyFile(m_certificateKeyPath);
    if (!certificateFile.open(QIODevice::WriteOnly | QIODevice::Truncate) || !keyFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        qWarning() << "Unable to write the certificate for the handover";
        return;
    }
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
    m_currentConnection->sendServerRedirection(info);
}

#include "moc_HandoverManager.cpp"
