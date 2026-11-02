// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <QLatin1StringView>

namespace KRdpKcm
{
using namespace Qt::StringLiterals;

namespace Defaults
{
inline constexpr int Port = 3389;
inline constexpr auto ListenAddress = "0.0.0.0"_L1;
inline constexpr auto CertificatePath = "/etc/krdp/server.crt"_L1;
inline constexpr auto CertificateKeyPath = "/etc/krdp/server.key"_L1;
inline constexpr auto ConfigPath = "/etc/xdg/krdpdispatcherrc"_L1;
inline constexpr auto ConfigDir = "/etc/xdg"_L1;
inline constexpr auto ConfigGroupGeneral = "General"_L1;
}

namespace Service
{
inline constexpr auto DispatcherServiceName = "org.kde.krdp-dispatcher.service"_L1;
inline constexpr auto ServerServiceName = "app-org.kde.krdpserver.service"_L1;
}

namespace DBus
{
inline constexpr auto SystemdDestination = "org.freedesktop.systemd1"_L1;
inline constexpr auto SystemdPath = "/org/freedesktop/systemd1"_L1;
inline constexpr auto SystemdManagerInterface = "org.freedesktop.systemd1.Manager"_L1;
inline constexpr auto SystemdUnitInterface = "org.freedesktop.systemd1.Unit"_L1;
inline constexpr auto SystemdPropertiesInterface = "org.freedesktop.DBus.Properties"_L1;

inline constexpr auto ServerServicePath = "/org/freedesktop/systemd1/unit/app_2dorg_2ekde_2ekrdpserver_2eservice"_L1;
inline constexpr auto DispatcherServicePath = "/org/freedesktop/systemd1/unit/org_2ekde_2ekrdp_2ddispatcher_2eservice"_L1;

inline constexpr auto MethodEnableUnitFiles = "EnableUnitFiles"_L1;
inline constexpr auto MethodDisableUnitFiles = "DisableUnitFiles"_L1;
inline constexpr auto MethodReload = "Reload"_L1;
inline constexpr auto MethodStartUnit = "StartUnit"_L1;
inline constexpr auto MethodStopUnit = "StopUnit"_L1;
inline constexpr auto MethodRestartUnit = "RestartUnit"_L1;
inline constexpr auto MethodGetUnitFileState = "GetUnitFileState"_L1;
inline constexpr auto MethodGet = "Get"_L1;

inline constexpr auto ModeReplace = "replace"_L1;
}

namespace Auth
{
inline constexpr auto ActionSave = "org.kde.kcontrol.kcmkrdpserver.save"_L1;
inline constexpr auto HelperId = "org.kde.kcontrol.kcmkrdpserver"_L1;

inline constexpr auto KeyEnableService = "enableService"_L1;
inline constexpr auto KeyEnableOnBoot = "enableOnBoot"_L1;
inline constexpr auto KeyRestartService = "restartService"_L1;
inline constexpr auto KeyListenAddress = "listenAddress"_L1;
inline constexpr auto KeyListenPort = "listenPort"_L1;
inline constexpr auto KeyTerminateOnDisconnect = "terminateOnDisconnect"_L1;
inline constexpr auto KeyAutogenerateCertificates = "autogenerateCertificates"_L1;
inline constexpr auto KeyCertificate = "certificate"_L1;
inline constexpr auto KeyCertificateKey = "certificateKey"_L1;
}

} // namespace KRdpKcm
