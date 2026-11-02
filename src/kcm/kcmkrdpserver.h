// SPDX-FileCopyrightText: 2024 Akseli Lahtinen <akselmo@akselmo.dev>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include "kcmconstants.h"
#include "krdpserversettings.h"
#include "usersmodel.h"
#include <KQuickManagedConfigModule>
#include <qt6keychain/keychain.h>
#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#endif

class KRDPServerConfigImpl;
class QAbstractItemModel;

namespace SystemdService
{
Q_NAMESPACE
enum Status {
    Unknown,
    Running,
    Stopped,
    Failed
};
Q_ENUM_NS(Status);
}

namespace H264
{
Q_NAMESPACE

enum Support {
    Unknown,
    Supported,
    Unsupported
};
Q_ENUM_NS(Support);
}

class KRDPServerConfig : public KQuickManagedConfigModule
{
    Q_OBJECT
public:
    static inline constexpr int DefaultRdpPort = KRdpKcm::Defaults::Port;

    explicit KRDPServerConfig(QObject *parent, const KPluginMetaData &data);
    ~KRDPServerConfig() override;

    Q_PROPERTY(int defaultRdpPort READ defaultRdpPort CONSTANT)

    Q_PROPERTY(SystemdService::Status serverStatus READ serverStatus NOTIFY serverStatusChanged);
    Q_PROPERTY(QString errorMessage READ errorMessage NOTIFY errorMessageChanged);

    Q_PROPERTY(QString hostName READ hostName CONSTANT)
    Q_PROPERTY(QString defaultCertificatePath READ defaultCertificatePath CONSTANT)
    Q_PROPERTY(QString defaultCertificateKeyPath READ defaultCertificateKeyPath CONSTANT)
    Q_PROPERTY(bool managementAvailable READ managementAvailable CONSTANT)
    Q_PROPERTY(H264::Support h264Support READ h264Support NOTIFY h264SupportChanged)

    Q_PROPERTY(QAbstractItemModel *users READ usersModel CONSTANT)

    // Remote Login (Dispatcher / System Service) properties
    Q_PROPERTY(SystemdService::Status remoteLoginStatus READ remoteLoginStatus NOTIFY remoteLoginStatusChanged)
    Q_PROPERTY(bool isRemoteLoginRunning READ isRemoteLoginRunning NOTIFY remoteLoginStatusChanged)
    Q_PROPERTY(bool remoteLoginEnabled READ remoteLoginEnabled WRITE setRemoteLoginEnabled NOTIFY remoteLoginEnabledChanged)
    Q_PROPERTY(QString remoteLoginErrorMessage READ remoteLoginErrorMessage NOTIFY remoteLoginErrorMessageChanged)

    Q_PROPERTY(QString dispatcherListenAddress READ dispatcherListenAddress WRITE setDispatcherListenAddress NOTIFY dispatcherSettingsChanged)
    Q_PROPERTY(int dispatcherListenPort READ dispatcherListenPort WRITE setDispatcherListenPort NOTIFY dispatcherSettingsChanged)
    Q_PROPERTY(
        bool dispatcherTerminateOnDisconnect READ dispatcherTerminateOnDisconnect WRITE setDispatcherTerminateOnDisconnect NOTIFY dispatcherSettingsChanged)
    Q_PROPERTY(bool dispatcherAutogenerateCertificates READ dispatcherAutogenerateCertificates WRITE setDispatcherAutogenerateCertificates NOTIFY
                   dispatcherSettingsChanged)
    Q_PROPERTY(QString dispatcherCertificate READ dispatcherCertificate WRITE setDispatcherCertificate NOTIFY dispatcherSettingsChanged)
    Q_PROPERTY(QString dispatcherCertificateKey READ dispatcherCertificateKey WRITE setDispatcherCertificateKey NOTIFY dispatcherSettingsChanged)

    Q_PROPERTY(QString defaultDispatcherCertificatePath READ defaultDispatcherCertificatePath CONSTANT)
    Q_PROPERTY(QString defaultDispatcherCertificateKeyPath READ defaultDispatcherCertificateKeyPath CONSTANT)

    Q_INVOKABLE QString toLocalFile(const QUrl &url);

    Q_INVOKABLE void modifyUser(const QString &oldUsername, const QString &newUsername, const QString &newPassword);
    Q_INVOKABLE void addUser(const QString &username, const QString &password);
    Q_INVOKABLE void deleteUser(const QString &username);
    Q_INVOKABLE bool userExists(const QString &username);

    Q_INVOKABLE void readPasswordFromWallet(const QString &user);
    void writePasswordToWallet(const QString &user, const QString &password);
    void deletePasswordFromWallet(const QString &user);

    Q_INVOKABLE QStringList listenAddressList();
    Q_INVOKABLE void toggleAutoconnect(const bool enabled);
    Q_INVOKABLE void toggleServer(const bool enabled);
    Q_INVOKABLE void restartServer();

    QString defaultCertificatePath() const;
    QString defaultCertificateKeyPath() const;
    Q_INVOKABLE void generateCertificate();
    Q_INVOKABLE void copyAddressToClipboard(const QString &address);
    Q_INVOKABLE KRDPServerSettings *settings() const
    {
        return m_serverSettings;
    };

    Q_INVOKABLE void updateServerStatus();
    SystemdService::Status serverStatus() const;
    Q_INVOKABLE [[nodiscard]] bool isServerRunning() const;

    QString errorMessage() const;

    // Remote Login (Dispatcher) methods
    SystemdService::Status remoteLoginStatus() const;
    Q_INVOKABLE [[nodiscard]] bool isRemoteLoginRunning() const;
    bool remoteLoginEnabled() const;
    void setRemoteLoginEnabled(bool enabled);
    QString remoteLoginErrorMessage() const;

    QString dispatcherListenAddress() const;
    void setDispatcherListenAddress(const QString &address);

    int dispatcherListenPort() const;
    void setDispatcherListenPort(int port);

    bool dispatcherTerminateOnDisconnect() const;
    void setDispatcherTerminateOnDisconnect(bool terminate);

    bool dispatcherAutogenerateCertificates() const;
    void setDispatcherAutogenerateCertificates(bool autoGen);

    QString dispatcherCertificate() const;
    void setDispatcherCertificate(const QString &cert);

    QString dispatcherCertificateKey() const;
    void setDispatcherCertificateKey(const QString &key);

    QString defaultDispatcherCertificatePath() const;
    QString defaultDispatcherCertificateKeyPath() const;

    Q_INVOKABLE void updateDispatcherStatus();
    Q_INVOKABLE void saveRemoteLogin(bool enableService, bool restartIfRunning, bool enableOnBoot = true);
    Q_INVOKABLE void toggleDispatcherAutostart(bool enableOnBoot);
    Q_INVOKABLE void loadDispatcherConfig();

    int defaultRdpPort() const
    {
        return DefaultRdpPort;
    }

    QString hostName() const;
    bool managementAvailable() const;
    H264::Support h264Support() const;
    QAbstractItemModel *usersModel() const
    {
        return m_usersModel;
    };

public Q_SLOTS:
    void save() override;
    void defaults() override;

Q_SIGNALS:
    void krdpServerSettingsChanged();
    void generateCertificateSucceeded();
    void generateCertificateFailed();
    void passwordLoaded(const QString &user, const QString &password);
    void keychainError(const QString &errorText);
    void serverStatusChanged();
    void errorMessageChanged();
    void isServerRunningChanged();
    void h264SupportChanged();

    void remoteLoginStatusChanged();
    void remoteLoginEnabledChanged();
    void remoteLoginErrorMessageChanged();
    void dispatcherSettingsChanged();
    void saveRemoteLoginSucceeded();
    void saveRemoteLoginFailed(const QString &errorText);

private:
    void probeH264Support();
    void setServerStatus(SystemdService::Status status);
    void setErrorMessage(const QString &errorMessage);
    void setRemoteLoginStatus(SystemdService::Status status);
    void setRemoteLoginErrorMessage(const QString &errorMessage);
    void createRestoreToken();
    QStringList getLastJournalEntries(const QString &unit, const QString &invocationId);
#ifdef HAVE_SYSTEMD
    QString journalValue(sd_journal *journal, const QString &field);
#endif

    KRDPServerSettings *m_serverSettings;
    UsersModel *m_usersModel;
    Q_SLOT void servicePropertiesChanged();
    Q_SLOT void dispatcherServicePropertiesChanged();
    H264::Support m_h264Support{H264::Unknown};
    SystemdService::Status m_currentServerStatus{SystemdService::Unknown};
    QString m_lastErrorMessage;

    SystemdService::Status m_remoteLoginStatus{SystemdService::Unknown};
    bool m_remoteLoginEnabled{false};
    QString m_remoteLoginErrorMessage;

    QString m_dispatcherListenAddress{KRdpKcm::Defaults::ListenAddress.toString()};
    int m_dispatcherListenPort{KRdpKcm::Defaults::Port};
    bool m_dispatcherTerminateOnDisconnect{true};
    bool m_dispatcherAutogenerateCertificates{true};
    QString m_dispatcherCertificate{KRdpKcm::Defaults::CertificatePath.toString()};
    QString m_dispatcherCertificateKey{KRdpKcm::Defaults::CertificateKeyPath.toString()};
    bool m_dispatcherSettingsModified{false};

    template<typename Output, typename Input>
    Output narrow(Input i)
    {
        Output o = i;
        if (i != Input(o)) {
            std::abort();
        }
        return o;
    }
};
