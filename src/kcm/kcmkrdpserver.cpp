// SPDX-FileCopyrightText: 2024 Akseli Lahtinen <akselmo@akselmo.dev>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "kcmkrdpserver.h"
#include "krdpkcm_logging.h"
#include "krdpserverdata.h"
#include "krdpserversettings.h"
#include <PipeWireRecord>

#include <KAuth/Action>
#include <KAuth/ExecuteJob>
#include <KConfig>
#include <KConfigGroup>
#include <KPluginFactory>
#include <QClipboard>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusPendingCallWatcher>
#include <QDBusReply>
#include <QDir>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QGuiApplication>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QProcess>
#include <QQmlEngine>
#include <QQuickItem>
#include <QQuickWindow>
#include <QtConcurrentRun>
#include <qt6keychain/keychain.h>

#include "org.freedesktop.impl.portal.PermissionStore.h"

using namespace Qt::StringLiterals;

K_PLUGIN_FACTORY_WITH_JSON(KRDPServerConfigFactory, "kcm_krdpserver.json", registerPlugin<KRDPServerConfig>(); registerPlugin<KRDPServerData>();)

static const char *const qmlUri = "org.kde.private.kcms.krdpserver";
static const QString passwordServiceName = QLatin1StringView("KRDP");

KRDPServerConfig::KRDPServerConfig(QObject *parent, const KPluginMetaData &data)
    : KQuickManagedConfigModule(parent, data)
    , m_serverSettings(new KRDPServerSettings(this))
    , m_usersModel(new UsersModel(m_serverSettings, this))
{
    setButtons(Help | Default);
    setSupportsInstantApply(true);

    qmlRegisterUncreatableMetaObject(H264::staticMetaObject, qmlUri, 1, 0, "H264Support", u"Error: only enums"_s);

    probeH264Support();

    if (m_serverSettings->autogenerateCertificates()) {
        generateCertificate();
    }

    QDBusConnection::sessionBus().connect(KRdpKcm::DBus::SystemdDestination.toString(),
                                          KRdpKcm::DBus::ServerServicePath.toString(),
                                          KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                          u"PropertiesChanged"_s,
                                          this,
                                          SLOT(servicePropertiesChanged()));

    loadDispatcherConfig();

    QDBusConnection::systemBus().connect(KRdpKcm::DBus::SystemdDestination.toString(),
                                         KRdpKcm::DBus::DispatcherServicePath.toString(),
                                         KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                         u"PropertiesChanged"_s,
                                         this,
                                         SLOT(dispatcherServicePropertiesChanged()));
    updateDispatcherStatus();
}

KRDPServerConfig::~KRDPServerConfig() = default;

QString KRDPServerConfig::toLocalFile(const QUrl &url)
{
    return url.toLocalFile();
}

void KRDPServerConfig::readPasswordFromWallet(const QString &user)
{
    if (user.isEmpty()) {
        return;
    }
    const auto readJob = new QKeychain::ReadPasswordJob(passwordServiceName, this);
    readJob->setKey(QLatin1StringView(user.toLatin1()));
    connect(readJob, &QKeychain::ReadPasswordJob::finished, this, [this, user, readJob]() {
        if (readJob->error() != QKeychain::Error::NoError) {
            qWarning(KRDPKCM) << "requestPassword: Failed to read password of " << user << " because of error: " << readJob->errorString();
            Q_EMIT keychainError(readJob->errorString());
            return;
        }
        Q_EMIT passwordLoaded(user, readJob->textData());
    });
    readJob->start();
}

void KRDPServerConfig::writePasswordToWallet(const QString &user, const QString &password)
{
    const auto writeJob = new QKeychain::WritePasswordJob(passwordServiceName);
    writeJob->setKey(QLatin1StringView(user.toLatin1()));
    writeJob->setTextData(password);
    writeJob->start();
    if (writeJob->error() != QKeychain::Error::NoError) {
        qWarning(KRDPKCM) << "requestPassword: Failed to write password of " << user << " because of error: " << writeJob->errorString();
        Q_EMIT keychainError(writeJob->errorString());
    }
}

void KRDPServerConfig::deletePasswordFromWallet(const QString &user)
{
    const auto deleteJob = new QKeychain::DeletePasswordJob(passwordServiceName);
    deleteJob->setKey(QLatin1StringView(user.toLatin1()));
    deleteJob->start();
    if (deleteJob->error() != QKeychain::Error::NoError) {
        qWarning(KRDPKCM) << "requestPassword: Failed to delete password of " << user << " because of error: " << deleteJob->errorString();
        Q_EMIT keychainError(deleteJob->errorString());
    }
}

void KRDPServerConfig::addUser(const QString &username, const QString &password)
{
    if (!username.isEmpty()) {
        auto userList = m_usersModel->users();
        userList.append(username);
        writePasswordToWallet(username, password);
        m_usersModel->setUsers(userList);
    }
    save();
}

void KRDPServerConfig::modifyUser(const QString &oldUsername, const QString &newUsername, const QString &newPassword)
{
    // Don't do anything if the new user is already in the list as a failsafe
    if (userExists(newUsername)) {
        return;
    }
    // If we have new username, we're removing the old one and adding the new one
    if (!newUsername.isEmpty()) {
        auto userList = m_usersModel->users();
        if (userList.contains(oldUsername)) {
            userList.removeAll(oldUsername);
        }
        userList.append(newUsername);
        deletePasswordFromWallet(oldUsername);
        writePasswordToWallet(newUsername, newPassword);
        m_usersModel->setUsers(userList);
    }
    // We change the password of the old user
    else {
        if (!oldUsername.isEmpty()) {
            writePasswordToWallet(oldUsername, newPassword);
        }
    }
    save();
}

void KRDPServerConfig::deleteUser(const QString &username)
{
    // Remove the old username
    if (!username.isEmpty()) {
        auto userList = m_usersModel->users();
        if (userList.contains(username)) {
            userList.removeAll(username);
        }
        deletePasswordFromWallet(username);
        m_usersModel->setUsers(userList);
    }
    save();
}

bool KRDPServerConfig::userExists(const QString &username)
{
    return m_usersModel->users().contains(username);
}

void KRDPServerConfig::save()
{
    KQuickManagedConfigModule::save();
    if (m_dispatcherSettingsModified) {
        saveRemoteLogin(m_remoteLoginEnabled, isRemoteLoginRunning(), m_remoteLoginEnabled);
    }
    Q_EMIT krdpServerSettingsChanged();
}

void KRDPServerConfig::defaults()
{
    // Do not reset list of users. This would not be needed
    // if we can get the list of users from wallet, instead
    // of saving it in this config
    auto userList = m_usersModel->users();
    KQuickManagedConfigModule::defaults();
    m_usersModel->setUsers(userList);

    setDispatcherListenAddress(KRdpKcm::Defaults::ListenAddress.toString());
    setDispatcherListenPort(KRdpKcm::Defaults::Port);
    setDispatcherTerminateOnDisconnect(true);
    setDispatcherAutogenerateCertificates(true);
    setDispatcherCertificate(KRdpKcm::Defaults::CertificatePath.toString());
    setDispatcherCertificateKey(KRdpKcm::Defaults::CertificateKeyPath.toString());
}

void KRDPServerConfig::createRestoreToken()
{
    static std::once_flag flag;
    std::call_once(flag, [this]() {
        auto iface = new OrgFreedesktopImplPortalPermissionStoreInterface(u"org.freedesktop.impl.portal.PermissionStore"_s,
                                                                          u"/org/freedesktop/impl/portal/PermissionStore"_s,
                                                                          QDBusConnection::sessionBus(),
                                                                          this);
        // WARNING: The app_id org.kde.krdpserver must match the service name on the systemd side!
        auto reply = iface->SetPermission(u"kde-authorized"_s, /* create = */ true, u"remote-desktop"_s, u"org.kde.krdpserver"_s, {u"yes"_s});
        auto watcher = new QDBusPendingCallWatcher(reply, this);
        connect(watcher, &QDBusPendingCallWatcher::finished, this, [watcher, iface]() {
            watcher->deleteLater();
            iface->deleteLater();
            QDBusPendingReply<> reply(*watcher);
            if (reply.isError()) {
                qCWarning(KRDPKCM) << "Failed to set pre-authorization in portal permission store" << reply.error().message();
            } else {
                qCDebug(KRDPKCM) << "Configured pre-authorization in portal permission store";
            }
        });
        return true;
    });
}

H264::Support KRDPServerConfig::h264Support() const
{
    return m_h264Support;
}

// Enumerating the available encoders initialises VA-API, which on some drivers
// opens the render node and builds a GPU context. That takes long enough to be
// noticeable, so keep it off the thread that is trying to show the UI.
void KRDPServerConfig::probeH264Support()
{
    auto watcher = new QFutureWatcher<bool>(this);
    connect(watcher, &QFutureWatcher<bool>::finished, this, [this, watcher] {
        watcher->deleteLater();
        const auto support = watcher->result() ? H264::Supported : H264::Unsupported;
        if (m_h264Support == support) {
            return;
        }
        m_h264Support = support;
        Q_EMIT h264SupportChanged();
    });
    watcher->setFuture(QtConcurrent::run([] {
        return PipeWireRecord().suggestedEncoders().contains(PipeWireRecord::H264Baseline);
    }));
}

QStringList KRDPServerConfig::listenAddressList()
{
    QStringList addressList;
    // Prepare default address
    const auto interfaces = QNetworkInterface::allInterfaces();
    for (const auto &interface : interfaces) {
        if (!interface.flags().testAnyFlag(QNetworkInterface::IsLoopBack)) {
            for (auto &address : interface.addressEntries()) {
                // Show only private ip addresses
                if (address.ip().isPrivateUse()) {
                    addressList.append(address.ip().toString());
                }
            }
        }
    }
    return addressList;
}

QString KRDPServerConfig::hostName() const
{
    QHostInfo info;
    return info.localHostName();
}

bool KRDPServerConfig::managementAvailable() const
{
    static bool managementAvailable = QDBusConnection::sessionBus().interface()->isServiceRegistered(u"org.freedesktop.systemd1"_s);
    return managementAvailable;
}

void KRDPServerConfig::toggleAutoconnect(const bool enabled)
{
    qDebug(KRDPKCM) << "Setting KRDP Server service autostart on login to " << enabled << "over QDBus";

    auto msg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                              KRdpKcm::DBus::SystemdPath.toString(),
                                              KRdpKcm::DBus::SystemdManagerInterface.toString(),
                                              enabled ? KRdpKcm::DBus::MethodEnableUnitFiles.toString() : KRdpKcm::DBus::MethodDisableUnitFiles.toString());
    if (enabled) {
        msg.setArguments({QStringList(KRdpKcm::Service::ServerServiceName.toString()), false, true});
    } else {
        msg.setArguments({QStringList(KRdpKcm::Service::ServerServiceName.toString()), false});
    }
    QDBusConnection::sessionBus().asyncCall(msg);

    if (enabled) {
        createRestoreToken();
    }
}

void KRDPServerConfig::toggleServer(const bool enabled)
{
    auto msg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                              KRdpKcm::DBus::ServerServicePath.toString(),
                                              KRdpKcm::DBus::SystemdUnitInterface.toString(),
                                              enabled ? u"Start"_s : u"Stop"_s);

    msg.setArguments({KRdpKcm::DBus::ModeReplace.toString()});
    qDebug(KRDPKCM) << "Toggling KRDP Server to " << enabled << "over QDBus";
    QDBusConnection::sessionBus().asyncCall(msg);

    if (enabled) {
        createRestoreToken();
    }
    updateServerStatus();
}

void KRDPServerConfig::restartServer()
{
    if (m_remoteLoginEnabled || isRemoteLoginRunning()) {
        qDebug(KRDPKCM) << "Restarting KRDP Dispatcher";
        saveRemoteLogin(true, true, m_remoteLoginEnabled);
        return;
    }
    qDebug(KRDPKCM) << "Restarting KRDP Server";
    auto restartMsg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                                     KRdpKcm::DBus::ServerServicePath.toString(),
                                                     KRdpKcm::DBus::SystemdUnitInterface.toString(),
                                                     u"Restart"_s);
    restartMsg.setArguments({KRdpKcm::DBus::ModeReplace.toString()});
    auto pendingCall = QDBusConnection::sessionBus().asyncCall(restartMsg);
    auto watcher = new QDBusPendingCallWatcher(pendingCall, this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [&](QDBusPendingCallWatcher *w) {
        updateServerStatus();
        w->deleteLater();
    });
}

QString KRDPServerConfig::defaultCertificatePath() const
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + u"/krdpserver/krdp.crt"_s;
}

QString KRDPServerConfig::defaultCertificateKeyPath() const
{
    return QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + u"/krdpserver/krdp.key"_s;
}

void KRDPServerConfig::generateCertificate()
{
    if (!m_serverSettings->certificate().isEmpty() || !m_serverSettings->certificateKey().isEmpty()) {
        return;
    }
    QDir(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)).mkpath(u"krdpserver"_s);
    QString certificatePath(defaultCertificatePath());
    QString certificateKeyPath(defaultCertificateKeyPath());
    qDebug(KRDPKCM) << "Generating certificate files to: " << certificatePath << " and " << certificateKeyPath;
    QProcess sslProcess;
    sslProcess.start(u"openssl"_s,
                     {
                         u"req"_s,
                         u"-nodes"_s,
                         u"-new"_s,
                         u"-x509"_s,
                         u"-keyout"_s,
                         certificateKeyPath,
                         u"-out"_s,
                         certificatePath,
                         u"-days"_s,
                         u"3650"_s,
                         u"-batch"_s,
                     });
    sslProcess.waitForFinished();

    m_serverSettings->setCertificate(certificatePath);
    m_serverSettings->setCertificateKey(certificateKeyPath);

    // Check that the path is valid
    if (QFileInfo::exists(certificatePath) && QFileInfo::exists(certificateKeyPath)) {
        qDebug(KRDPKCM) << "Certificate generated; ready to accept connections.";
        Q_EMIT generateCertificateSucceeded();
    } else {
        qCritical(KRDPKCM) << "Could not generate a certificate. A valid TLS certificate and key should be provided.";
        Q_EMIT generateCertificateFailed();
    }

    m_serverSettings->save();
}

void KRDPServerConfig::updateServerStatus()
{
    auto msg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                              KRdpKcm::DBus::ServerServicePath.toString(),
                                              KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                              KRdpKcm::DBus::MethodGet.toString());
    msg.setArguments({KRdpKcm::DBus::SystemdUnitInterface.toString(), u"ActiveState"_s});

    QDBusPendingCall pcall = QDBusConnection::sessionBus().asyncCall(msg);
    auto watcher = new QDBusPendingCallWatcher(pcall, this);

    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<QVariant> reply(*w);
        const QString replyString = reply.value().toString();
        if (replyString == "active"_L1 || replyString == "reloading"_L1) {
            setServerStatus(SystemdService::Status::Running);
        } else if (replyString == "failed"_L1) {
            auto invocationIdMsg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                                                  KRdpKcm::DBus::ServerServicePath.toString(),
                                                                  KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                                                  KRdpKcm::DBus::MethodGet.toString());
            invocationIdMsg.setArguments({KRdpKcm::DBus::SystemdUnitInterface.toString(), u"InvocationID"_s});

            QDBusPendingCall pcall = QDBusConnection::sessionBus().asyncCall(invocationIdMsg);
            auto idWatcher = new QDBusPendingCallWatcher(pcall, this);
            connect(idWatcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *w) {
                QDBusPendingReply<QDBusVariant> reply(*w);
                const auto replyString = QString::fromUtf8(reply.value().variant().toByteArray().toHex());
                setErrorMessage(getLastJournalEntries(KRdpKcm::Service::ServerServiceName.toString(), replyString).join("\n"_L1));
            });

            setServerStatus(SystemdService::Status::Failed);
        } else if (replyString == "inactive"_L1) {
            setServerStatus(SystemdService::Status::Stopped);
        } else {
            setServerStatus(SystemdService::Status::Unknown);
            qWarning(KRDPKCM) << "Systemd unit replied with unknown reply: " << replyString;
        }
        w->deleteLater();
    });
}

SystemdService::Status KRDPServerConfig::serverStatus() const
{
    return m_currentServerStatus;
}

void KRDPServerConfig::setServerStatus(SystemdService::Status status)
{
    if (m_currentServerStatus != status) {
        m_currentServerStatus = status;
        Q_EMIT serverStatusChanged();
    }
}

bool KRDPServerConfig::isServerRunning() const
{
    return m_currentServerStatus == SystemdService::Running;
}

QString KRDPServerConfig::errorMessage() const
{
    return m_lastErrorMessage;
}

void KRDPServerConfig::setErrorMessage(const QString &errorMessage)
{
    m_lastErrorMessage = errorMessage;
    Q_EMIT errorMessageChanged();
}

#ifdef HAVE_SYSTEMD
QString KRDPServerConfig::journalValue(sd_journal *journal, const QString &field)
{
    size_t length = 0;
    const void *data = nullptr;
    auto returnValue = sd_journal_get_data(journal, field.toStdString().c_str(), &data, &length);
    QString line;
    if (returnValue == 0) {
        line = (QString::fromUtf8(static_cast<const char *>(data), narrow<qsizetype>(length)).section(u'=', 1));
    }
    return line;
}

QStringList KRDPServerConfig::getLastJournalEntries(const QString &unit, const QString &invocationId)
{
    sd_journal *journal = nullptr;
    auto cleanup = qScopeGuard([journal] {
        sd_journal_close(journal);
    });

    int returnValue = sd_journal_open(&journal, (SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_CURRENT_USER));
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to open journal to read the error messages.";
        return {};
    }

    sd_journal_flush_matches(journal);

    const QString match1 = QStringLiteral("USER_UNIT=%1").arg(unit);
    returnValue = sd_journal_add_match(journal, match1.toUtf8().constData(), 0);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a match " << match1 << " to journal, return value is " << returnValue;
        return {};
    }

    returnValue = sd_journal_add_disjunction(journal);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a disjunction to journal, return value is " << returnValue;
        return {};
    }

    const QString match2 = QStringLiteral("_SYSTEMD_USER_UNIT=%1").arg(unit);
    returnValue = sd_journal_add_match(journal, match2.toUtf8().constData(), 0);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a match " << match2 << " to journal, return value is " << returnValue;
        return {};
    }

    returnValue = sd_journal_add_conjunction(journal);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a conjunction to journal, return value is " << returnValue;
        return {};
    }

    const QString match3 = QStringLiteral("_SYSTEMD_INVOCATION_ID=%1").arg(invocationId);
    returnValue = sd_journal_add_match(journal, match3.toUtf8().constData(), 0);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a match " << match3 << " to journal, return value is " << returnValue;
        return {};
    }

    returnValue = sd_journal_add_conjunction(journal);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a conjunction to journal, return value is " << returnValue;
        return {};
    }

    const QString match4 = QStringLiteral("SYSLOG_IDENTIFIER=krdpserver");
    returnValue = sd_journal_add_match(journal, match4.toUtf8().constData(), 0);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Failed to add a match " << match4 << " to journal, return value is " << returnValue;
        return {};
    }

    returnValue = sd_journal_seek_tail(journal);
    if (returnValue != 0) {
        qCWarning(KRDPKCM) << "Could not seek the tail of the journal, return value is " << returnValue;
        return {};
    }

    QStringList reply;

    while (sd_journal_previous(journal) != 0) {
        // Get the message itself
        reply << journalValue(journal, "MESSAGE"_L1);
    }

    if (reply.isEmpty()) {
        qCDebug(KRDPKCM) << "Journal for KRDP Unit with invocationId" << invocationId << "is empty.";
    } else {
        qCDebug(KRDPKCM) << "Journal for KRPD Unit with invocationId" << invocationId << "replied:" << reply;
    }

    return reply;
}
#else
QStringList KRDPServerConfig::getLastJournalEntries(const QString &unit, const QString &invocationId)
{
    Q_UNUSED(unit);
    Q_UNUSED(invocationId);
    return {};
}
#endif

void KRDPServerConfig::copyAddressToClipboard(const QString &address)
{
    QGuiApplication::clipboard()->setText(address.trimmed());
}

void KRDPServerConfig::servicePropertiesChanged()
{
    updateServerStatus();
}

void KRDPServerConfig::dispatcherServicePropertiesChanged()
{
    updateDispatcherStatus();
}

SystemdService::Status KRDPServerConfig::remoteLoginStatus() const
{
    return m_remoteLoginStatus;
}

void KRDPServerConfig::setRemoteLoginStatus(SystemdService::Status status)
{
    if (m_remoteLoginStatus != status) {
        m_remoteLoginStatus = status;
        Q_EMIT remoteLoginStatusChanged();
    }
}

bool KRDPServerConfig::isRemoteLoginRunning() const
{
    return m_remoteLoginStatus == SystemdService::Running;
}

bool KRDPServerConfig::remoteLoginEnabled() const
{
    return m_remoteLoginEnabled;
}

void KRDPServerConfig::setRemoteLoginEnabled(bool enabled)
{
    if (m_remoteLoginEnabled != enabled) {
        m_remoteLoginEnabled = enabled;
        Q_EMIT remoteLoginEnabledChanged();
    }
}

QString KRDPServerConfig::remoteLoginErrorMessage() const
{
    return m_remoteLoginErrorMessage;
}

void KRDPServerConfig::setRemoteLoginErrorMessage(const QString &errorMessage)
{
    if (m_remoteLoginErrorMessage != errorMessage) {
        m_remoteLoginErrorMessage = errorMessage;
        Q_EMIT remoteLoginErrorMessageChanged();
    }
}

QString KRDPServerConfig::dispatcherListenAddress() const
{
    return m_dispatcherListenAddress;
}

void KRDPServerConfig::setDispatcherListenAddress(const QString &address)
{
    if (m_dispatcherListenAddress != address) {
        m_dispatcherListenAddress = address;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

int KRDPServerConfig::dispatcherListenPort() const
{
    return m_dispatcherListenPort;
}

void KRDPServerConfig::setDispatcherListenPort(int port)
{
    if (m_dispatcherListenPort != port) {
        m_dispatcherListenPort = port;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

bool KRDPServerConfig::dispatcherTerminateOnDisconnect() const
{
    return m_dispatcherTerminateOnDisconnect;
}

void KRDPServerConfig::setDispatcherTerminateOnDisconnect(bool terminate)
{
    if (m_dispatcherTerminateOnDisconnect != terminate) {
        m_dispatcherTerminateOnDisconnect = terminate;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

bool KRDPServerConfig::dispatcherAutogenerateCertificates() const
{
    return m_dispatcherAutogenerateCertificates;
}

void KRDPServerConfig::setDispatcherAutogenerateCertificates(bool autoGen)
{
    if (m_dispatcherAutogenerateCertificates != autoGen) {
        m_dispatcherAutogenerateCertificates = autoGen;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

QString KRDPServerConfig::dispatcherCertificate() const
{
    return m_dispatcherCertificate;
}

void KRDPServerConfig::setDispatcherCertificate(const QString &cert)
{
    if (m_dispatcherCertificate != cert) {
        m_dispatcherCertificate = cert;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

QString KRDPServerConfig::dispatcherCertificateKey() const
{
    return m_dispatcherCertificateKey;
}

void KRDPServerConfig::setDispatcherCertificateKey(const QString &key)
{
    if (m_dispatcherCertificateKey != key) {
        m_dispatcherCertificateKey = key;
        m_dispatcherSettingsModified = true;
        setNeedsSave(true);
        Q_EMIT dispatcherSettingsChanged();
    }
}

QString KRDPServerConfig::defaultDispatcherCertificatePath() const
{
    return KRdpKcm::Defaults::CertificatePath.toString();
}

QString KRDPServerConfig::defaultDispatcherCertificateKeyPath() const
{
    return KRdpKcm::Defaults::CertificateKeyPath.toString();
}

void KRDPServerConfig::loadDispatcherConfig()
{
    KConfig config(KRdpKcm::Defaults::ConfigPath.toString(), KConfig::SimpleConfig);
    KConfigGroup group = config.group(KRdpKcm::Defaults::ConfigGroupGeneral);

    m_dispatcherListenAddress = group.readEntry(KRdpKcm::Defaults::EntryListenAddress, KRdpKcm::Defaults::ListenAddress.toString());
    m_dispatcherListenPort = group.readEntry(KRdpKcm::Defaults::EntryListenPort, KRdpKcm::Defaults::Port);
    m_dispatcherTerminateOnDisconnect = group.readEntry(KRdpKcm::Defaults::EntryTerminateOnDisconnect, true);
    m_dispatcherAutogenerateCertificates = group.readEntry(KRdpKcm::Defaults::EntryAutogenerateCertificates, true);
    m_dispatcherCertificate = group.readEntry(KRdpKcm::Defaults::EntryCertificate, KRdpKcm::Defaults::CertificatePath.toString());
    m_dispatcherCertificateKey = group.readEntry(KRdpKcm::Defaults::EntryCertificateKey, KRdpKcm::Defaults::CertificateKeyPath.toString());
    m_dispatcherSettingsModified = false;
    Q_EMIT dispatcherSettingsChanged();
}

void KRDPServerConfig::updateDispatcherStatus()
{
    auto msg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                              KRdpKcm::DBus::DispatcherServicePath.toString(),
                                              KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                              KRdpKcm::DBus::MethodGet.toString());
    msg.setArguments({KRdpKcm::DBus::SystemdUnitInterface.toString(), u"ActiveState"_s});

    QDBusPendingCall pcall = QDBusConnection::systemBus().asyncCall(msg);
    auto watcher = new QDBusPendingCallWatcher(pcall, this);

    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<QVariant> reply(*w);
        const QString replyString = reply.value().toString();
        if (replyString == "active"_L1 || replyString == "reloading"_L1) {
            setRemoteLoginStatus(SystemdService::Status::Running);
        } else if (replyString == "failed"_L1) {
            setRemoteLoginStatus(SystemdService::Status::Failed);
            auto invocationIdMsg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                                                  KRdpKcm::DBus::DispatcherServicePath.toString(),
                                                                  KRdpKcm::DBus::SystemdPropertiesInterface.toString(),
                                                                  KRdpKcm::DBus::MethodGet.toString());
            invocationIdMsg.setArguments({KRdpKcm::DBus::SystemdUnitInterface.toString(), u"InvocationID"_s});

            QDBusPendingCall idCall = QDBusConnection::systemBus().asyncCall(invocationIdMsg);
            auto idWatcher = new QDBusPendingCallWatcher(idCall, this);
            connect(idWatcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *iw) {
                QDBusPendingReply<QDBusVariant> idReply(*iw);
                const auto invId = QString::fromUtf8(idReply.value().variant().toByteArray().toHex());
                setRemoteLoginErrorMessage(getLastJournalEntries(KRdpKcm::Service::DispatcherServiceName.toString(), invId).join(u"\n"_s));
                iw->deleteLater();
            });
        } else if (replyString == "inactive"_L1) {
            setRemoteLoginStatus(SystemdService::Status::Stopped);
        } else {
            setRemoteLoginStatus(SystemdService::Status::Unknown);
        }
        w->deleteLater();
    });

    auto stateMsg = QDBusMessage::createMethodCall(KRdpKcm::DBus::SystemdDestination.toString(),
                                                   KRdpKcm::DBus::SystemdPath.toString(),
                                                   KRdpKcm::DBus::SystemdManagerInterface.toString(),
                                                   KRdpKcm::DBus::MethodGetUnitFileState.toString());
    stateMsg.setArguments({KRdpKcm::Service::DispatcherServiceName.toString()});
    QDBusPendingCall stateCall = QDBusConnection::systemBus().asyncCall(stateMsg);
    auto stateWatcher = new QDBusPendingCallWatcher(stateCall, this);
    connect(stateWatcher, &QDBusPendingCallWatcher::finished, this, [this](QDBusPendingCallWatcher *w) {
        QDBusPendingReply<QString> stateReply(*w);
        if (!stateReply.isError()) {
            const QString state = stateReply.value();
            setRemoteLoginEnabled(state == "enabled"_L1 || state == "enabled-runtime"_L1);
        }
        w->deleteLater();
    });
}

void KRDPServerConfig::saveRemoteLogin(bool enableService, bool restartIfRunning, bool enableOnBoot)
{
    auto action = KAuth::Action(KRdpKcm::Auth::ActionSave.toString());
    action.setHelperId(KRdpKcm::Auth::HelperId.toString());
    if (mainUi() && mainUi()->window()) {
        action.setParentWindow(mainUi()->window());
    }

    QVariantMap args;
    args[KRdpKcm::Auth::KeyEnableService.toString()] = enableService;
    args[KRdpKcm::Auth::KeyEnableOnBoot.toString()] = enableOnBoot;
    args[KRdpKcm::Auth::KeyListenAddress.toString()] = m_dispatcherListenAddress;
    args[KRdpKcm::Auth::KeyListenPort.toString()] = m_dispatcherListenPort;
    args[KRdpKcm::Auth::KeyTerminateOnDisconnect.toString()] = m_dispatcherTerminateOnDisconnect;
    args[KRdpKcm::Auth::KeyAutogenerateCertificates.toString()] = m_dispatcherAutogenerateCertificates;
    args[KRdpKcm::Auth::KeyCertificate.toString()] = m_dispatcherCertificate;
    args[KRdpKcm::Auth::KeyCertificateKey.toString()] = m_dispatcherCertificateKey;
    if (restartIfRunning) {
        args[KRdpKcm::Auth::KeyRestartService.toString()] = true;
    }
    action.setArguments(args);

    auto *job = action.execute();
    connect(job, &KJob::result, this, [this, job, enableOnBoot]() {
        if (job->error()) {
            qCWarning(KRDPKCM) << "KAuth saveRemoteLogin failed:" << job->errorString();
            setNeedsSave(true);
            Q_EMIT saveRemoteLoginFailed(job->errorString());
            updateDispatcherStatus();
        } else {
            qCDebug(KRDPKCM) << "KAuth saveRemoteLogin succeeded";
            m_dispatcherSettingsModified = false;
            setNeedsSave(false);
            setRemoteLoginEnabled(enableOnBoot);
            Q_EMIT saveRemoteLoginSucceeded();
            updateDispatcherStatus();
        }
    });
    job->start();
}

void KRDPServerConfig::toggleDispatcherAutostart(bool enableOnBoot)
{
    saveRemoteLogin(isRemoteLoginRunning(), false, enableOnBoot);
}

#include "kcmkrdpserver.moc"
