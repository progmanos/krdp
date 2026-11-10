/*
    SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
    SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL
 */

#include "krdpserverauthhelper.h"
#include "../kcmconstants.h"

#include <filesystem>

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>

#include <KConfig>
#include <KConfigGroup>

namespace
{
bool generateCertificateIfMissing(const QString &certPath, const QString &keyPath)
{
    using namespace KRdpKcm;

    if (QFile::exists(certPath) && QFile::exists(keyPath)) {
        return true;
    }

    const QFileInfo certInfo(certPath);
    QDir().mkpath(certInfo.absolutePath());

    const int exitCode = QProcess::execute(Auth::OpenSslBinary.toString(),
                                           {Auth::OpenSslReqCmd.toString(),
                                            Auth::OpenSslNodesFlag.toString(),
                                            Auth::OpenSslX509Flag.toString(),
                                            Auth::OpenSslNewKeyFlag.toString(),
                                            Auth::OpenSslRsa2048.toString(),
                                            Auth::OpenSslKeyOutFlag.toString(),
                                            keyPath,
                                            Auth::OpenSslOutFlag.toString(),
                                            certPath,
                                            Auth::OpenSslDaysFlag.toString(),
                                            Auth::OpenSslValidityDays.toString(),
                                            Auth::OpenSslSubjFlag.toString(),
                                            Auth::OpenSslSubjValue.toString()});

    if (exitCode == 0) {
        QFile::setPermissions(keyPath, QFile::ReadOwner | QFile::WriteOwner);
        QFile::setPermissions(certPath, QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther);
        return true;
    }
    return false;
}
}

ActionReply KRDPServerAuthHelper::save(const QVariantMap &args)
{
    using namespace KRdpKcm;

    // Write system configuration file /etc/xdg/krdpdispatcherrc
    QDir().mkpath(Defaults::ConfigDir.toString());
    KConfig config(Defaults::ConfigPath.toString(), KConfig::SimpleConfig);
    KConfigGroup group = config.group(Defaults::ConfigGroupGeneral);

    if (args.contains(Auth::KeyListenAddress.toString())) {
        group.writeEntry(Defaults::EntryListenAddress, args.value(Auth::KeyListenAddress.toString()).toString());
    }
    if (args.contains(Auth::KeyListenPort.toString())) {
        group.writeEntry(Defaults::EntryListenPort, args.value(Auth::KeyListenPort.toString()).toInt());
    }
    if (args.contains(Auth::KeyTerminateOnDisconnect.toString())) {
        group.writeEntry(Defaults::EntryTerminateOnDisconnect, args.value(Auth::KeyTerminateOnDisconnect.toString()).toBool());
    }
    if (args.contains(Auth::KeyAutogenerateCertificates.toString())) {
        group.writeEntry(Defaults::EntryAutogenerateCertificates, args.value(Auth::KeyAutogenerateCertificates.toString()).toBool());
    }

    const QString certPath = args.value(Auth::KeyCertificate.toString(), Defaults::CertificatePath.toString()).toString();
    const QString keyPath = args.value(Auth::KeyCertificateKey.toString(), Defaults::CertificateKeyPath.toString()).toString();

    group.writeEntry(Defaults::EntryCertificate, certPath);
    group.writeEntry(Defaults::EntryCertificateKey, keyPath);
    config.sync();

    if (args.value(Auth::KeyAutogenerateCertificates.toString(), true).toBool()) {
        generateCertificateIfMissing(certPath, keyPath);
    }

    // Manage systemd service if requested
    if (args.contains(Auth::KeyEnableService.toString())) {
        const bool enable = args.value(Auth::KeyEnableService.toString()).toBool();
        const bool enableOnBoot = args.value(Auth::KeyEnableOnBoot.toString(), enable).toBool();
        auto systemBus = QDBusConnection::systemBus();
        const QString serviceName = Service::DispatcherServiceName.toString();

        if (enable) {
            if (enableOnBoot) {
                auto enableMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                                DBus::SystemdPath.toString(),
                                                                DBus::SystemdManagerInterface.toString(),
                                                                DBus::MethodEnableUnitFiles.toString());
                enableMsg << QStringList{serviceName} << false << true;
                auto reply = systemBus.call(enableMsg);
                if (reply.type() == QDBusMessage::ErrorMessage) {
                    qWarning() << "EnableUnitFiles failed:" << reply.errorMessage();
                }
            } else {
                auto disableMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                                 DBus::SystemdPath.toString(),
                                                                 DBus::SystemdManagerInterface.toString(),
                                                                 DBus::MethodDisableUnitFiles.toString());
                disableMsg << QStringList{serviceName} << false;
                auto reply = systemBus.call(disableMsg);
                if (reply.type() == QDBusMessage::ErrorMessage) {
                    qWarning() << "DisableUnitFiles failed:" << reply.errorMessage();
                }
            }

            auto reloadMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                            DBus::SystemdPath.toString(),
                                                            DBus::SystemdManagerInterface.toString(),
                                                            DBus::MethodReload.toString());
            systemBus.call(reloadMsg);

            const QString actionName =
                args.value(Auth::KeyRestartService.toString(), false).toBool() ? DBus::MethodRestartUnit.toString() : DBus::MethodStartUnit.toString();
            auto startMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                           DBus::SystemdPath.toString(),
                                                           DBus::SystemdManagerInterface.toString(),
                                                           actionName);
            startMsg << serviceName << DBus::ModeReplace.toString();
            auto reply = systemBus.call(startMsg);
            if (reply.type() == QDBusMessage::ErrorMessage) {
                qWarning() << actionName << "failed:" << reply.errorMessage();
            }
        } else {
            auto stopMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                          DBus::SystemdPath.toString(),
                                                          DBus::SystemdManagerInterface.toString(),
                                                          DBus::MethodStopUnit.toString());
            stopMsg << serviceName << DBus::ModeReplace.toString();
            auto stopReply = systemBus.call(stopMsg);
            if (stopReply.type() == QDBusMessage::ErrorMessage) {
                qWarning() << "StopUnit failed:" << stopReply.errorMessage();
            }

            auto disableMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                             DBus::SystemdPath.toString(),
                                                             DBus::SystemdManagerInterface.toString(),
                                                             DBus::MethodDisableUnitFiles.toString());
            disableMsg << QStringList{serviceName} << false;
            auto disReply = systemBus.call(disableMsg);
            if (disReply.type() == QDBusMessage::ErrorMessage) {
                qWarning() << "DisableUnitFiles failed:" << disReply.errorMessage();
            }

            auto reloadMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                            DBus::SystemdPath.toString(),
                                                            DBus::SystemdManagerInterface.toString(),
                                                            DBus::MethodReload.toString());
            systemBus.call(reloadMsg);
        }
    } else if (args.value(Auth::KeyRestartService.toString(), false).toBool()) {
        auto restartMsg = QDBusMessage::createMethodCall(DBus::SystemdDestination.toString(),
                                                         DBus::SystemdPath.toString(),
                                                         DBus::SystemdManagerInterface.toString(),
                                                         DBus::MethodRestartUnit.toString());
        restartMsg << Service::DispatcherServiceName.toString() << DBus::ModeReplace.toString();
        QDBusConnection::systemBus().call(restartMsg);
    }

    return ActionReply::SuccessReply();
}

KAUTH_HELPER_MAIN("org.kde.kcontrol.kcmkrdpserver", KRDPServerAuthHelper)
