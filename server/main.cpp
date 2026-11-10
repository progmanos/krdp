// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <csignal>
#include <filesystem>

#include <QApplication>
#include <QCommandLineParser>
#include <QRegularExpression>

#include <KAboutData>
#include <KCrash>
#include <KSharedConfig>
#include <KSignalHandler>

#include <qt6keychain/keychain.h>

#include "HandoverManager.h"
#include "Server.h"
#include "SessionController.h"
#include "krdp_version.h"
#include "krdpserversettings.h"

using namespace Qt::StringLiterals;

namespace
{
constexpr auto kEnvRemoteId = "PLASMALOGIN_REMOTE_ID";
constexpr auto kEnvIsRemote = "PLASMALOGIN_IS_REMOTE";
constexpr auto kEnvXdgSeat = "XDG_SEAT";
constexpr auto kEnvXdgSessionClass = "XDG_SESSION_CLASS";

constexpr auto kRemoteSeatUnderscorePrefix = "seat_remote"_L1;
constexpr auto kRemoteSeatHyphenPrefix = "seat-remote"_L1;
constexpr auto kGreeterSessionClass = "greeter"_L1;
constexpr int kEnvEnabledValue = 1;

constexpr auto kDispatcherConfigFileName = "krdpdispatcherrc"_L1;
constexpr auto kGeneralConfigGroup = "General"_L1;
constexpr auto kTerminateOnDisconnectKey = "TerminateOnDisconnect";

constexpr auto kAppName = "krdp-server"_L1;
constexpr auto kAppDisplayName = "KRDP Server"_L1;
constexpr auto kDesktopFileName = "org.kde.krdpserver"_L1;

constexpr auto kAppDescription =
    "An RDP server that exposes the current desktop session over the RDP protocol.\nNote that a valid TLS certificate and key is needed. If not provided, a temporary certificate will be generated."_L1;

constexpr auto kOptionUsername = "username"_L1;
constexpr auto kOptionUsernameShort = "u"_L1;
constexpr auto kOptionUsernameDesc = "The username to use for login"_L1;

constexpr auto kOptionPassword = "password"_L1;
constexpr auto kOptionPasswordShort = "p"_L1;
constexpr auto kOptionPasswordDesc = "The password to use for login. Requires username to be passed as well."_L1;

constexpr auto kOptionAddress = "address"_L1;
constexpr auto kOptionAddressDesc = "The address to listen on for connections. Defaults to 0.0.0.0"_L1;

constexpr auto kOptionPort = "port"_L1;
constexpr auto kOptionPortDesc = "The port to use for connections. Defaults to 3389."_L1;
constexpr auto kDefaultPort = "3389"_L1;

constexpr auto kOptionCertificate = "certificate"_L1;
constexpr auto kOptionCertificateDesc = "The TLS certificate file to use."_L1;
constexpr auto kDefaultCertificate = "server.crt"_L1;

constexpr auto kOptionCertificateKey = "certificate-key"_L1;
constexpr auto kOptionCertificateKeyDesc = "The TLS certificate key to use."_L1;
constexpr auto kDefaultCertificateKey = "server.key"_L1;

constexpr auto kOptionMonitor = "monitor"_L1;
constexpr auto kOptionMonitorDesc = "The index of the monitor to use when streaming."_L1;
constexpr auto kDefaultMonitor = "-1"_L1;

constexpr auto kOptionVirtualMonitor = "virtual-monitor"_L1;
constexpr auto kOptionVirtualMonitorDesc = "Creates a new virtual output to connect to (WIDTHxHEIGHT@SCALE, e.g. 1920x1080@1). Incompatible with --monitor."_L1;
constexpr auto kOptionVirtualMonitorValueName = "data"_L1;
constexpr auto kDefaultVirtualMonitorValue = "1920x1080@1"_L1;

constexpr auto kOptionMode = "mode"_L1;
constexpr auto kOptionModeDesc = "The operation mode to use: RemoteAccess, SharedAccess, or AdditionalDisplay."_L1;

constexpr auto kOptionQuality = "quality"_L1;
constexpr auto kOptionQualityDesc =
    "Encoding quality of the stream, from 0 (lowest) to 100 (highest). With adaptive quality (the default) this is the upper bound; with --static-quality it is the fixed quality."_L1;

constexpr auto kOptionAdaptiveQuality = "adaptive-quality"_L1;
constexpr auto kOptionAdaptiveQualityDesc =
    "Adjust the encoding quality at runtime based on the client's network conditions, up to --quality. On by default; only matters if disabled in the configuration."_L1;

constexpr auto kOptionStaticQuality = "static-quality"_L1;
constexpr auto kOptionStaticQualityDesc = "Pin the encoding quality at --quality instead of adapting it to the client's network conditions."_L1;

constexpr auto kOptionHandover = "handover"_L1;
constexpr auto kOptionHandoverDesc =
    "Run as the destination of a remote login handover with the system KRdp dispatcher, instead of listening for connections."_L1;

constexpr auto kOptionRemoteId = "remote-id"_L1;
constexpr auto kOptionRemoteIdDesc = "The remote id of the client to serve. Must be used with --handover."_L1;

constexpr auto kOptionTerminateOnDisconnect = "terminate-on-disconnect"_L1;
constexpr auto kOptionTerminateOnDisconnectDesc = "Terminate the user session when the client disconnects (default in handover mode)."_L1;

constexpr auto kOptionNoTerminateOnDisconnect = "no-terminate-on-disconnect"_L1;
constexpr auto kOptionNoTerminateOnDisconnectDesc = "Do not terminate the user session when the client disconnects."_L1;

constexpr auto kOptionPlasma = "plasma"_L1;
constexpr auto kOptionPlasmaDesc = "Use Plasma protocols instead of XDP"_L1;

constexpr auto kKeychainService = "KRDP"_L1;
constexpr auto kModeRemoteAccess = "RemoteAccess"_L1;
constexpr auto kModeSharedAccess = "SharedAccess"_L1;
constexpr auto kModeAdditionalDisplay = "AdditionalDisplay"_L1;

static const auto kVirtualMonitorRegexPattern = QStringLiteral(R"((\d+)x(\d+)@([\d.]+))");
const QRegularExpression kVirtualMonitorPattern(kVirtualMonitorRegexPattern);
}

static std::optional<SessionController::OperationMode> parseOperationMode(QAnyStringView value)
{
    if (value == kModeRemoteAccess) {
        return SessionController::OperationMode::RemoteAccess;
    }
    if (value == kModeSharedAccess) {
        return SessionController::OperationMode::SharedAccess;
    }
    if (value == kModeAdditionalDisplay) {
        return SessionController::OperationMode::AdditionalDisplay;
    }

    return std::nullopt;
}

int main(int argc, char **argv)
{
    QApplication application{argc, argv};
    application.setApplicationName(kAppName.toString());
    application.setApplicationDisplayName(kAppDisplayName.toString());

    KAboutData about(kAppName.toString(), kAppDisplayName.toString(), QStringLiteral(KRdp_VERSION_STRING));
    about.setDesktopFileName(kDesktopFileName.toString());
    KAboutData::setApplicationData(about);

    KCrash::initialize();

    QCommandLineParser parser;
    parser.setApplicationDescription(kAppDescription.toString());
    parser.addOptions({
        {{kOptionUsernameShort.toString(), kOptionUsername.toString()}, kOptionUsernameDesc.toString(), kOptionUsername.toString()},
        {{kOptionPasswordShort.toString(), kOptionPassword.toString()}, kOptionPasswordDesc.toString(), kOptionPassword.toString()},
        {kOptionAddress.toString(), kOptionAddressDesc.toString(), kOptionAddress.toString()},
        {kOptionPort.toString(), kOptionPortDesc.toString(), kOptionPort.toString(), kDefaultPort.toString()},
        {kOptionCertificate.toString(), kOptionCertificateDesc.toString(), kOptionCertificate.toString(), kDefaultCertificate.toString()},
        {kOptionCertificateKey.toString(), kOptionCertificateKeyDesc.toString(), kOptionCertificateKey.toString(), kDefaultCertificateKey.toString()},
        {kOptionMonitor.toString(), kOptionMonitorDesc.toString(), kOptionMonitor.toString(), kDefaultMonitor.toString()},
        {kOptionVirtualMonitor.toString(),
         kOptionVirtualMonitorDesc.toString(),
         kOptionVirtualMonitorValueName.toString(),
         kDefaultVirtualMonitorValue.toString()},
        {kOptionMode.toString(), kOptionModeDesc.toString(), kOptionMode.toString()},
        {kOptionQuality.toString(), kOptionQualityDesc.toString(), kOptionQuality.toString()},
        {kOptionAdaptiveQuality.toString(), kOptionAdaptiveQualityDesc.toString()},
        {kOptionStaticQuality.toString(), kOptionStaticQualityDesc.toString()},
        {kOptionHandover.toString(), kOptionHandoverDesc.toString()},
        {kOptionRemoteId.toString(), kOptionRemoteIdDesc.toString(), kOptionRemoteId.toString()},
        {kOptionTerminateOnDisconnect.toString(), kOptionTerminateOnDisconnectDesc.toString()},
        {kOptionNoTerminateOnDisconnect.toString(), kOptionNoTerminateOnDisconnectDesc.toString()},
#ifdef WITH_PLASMA_SESSION
        {kOptionPlasma.toString(), kOptionPlasmaDesc.toString()},
#endif
    });
    about.setupCommandLine(&parser);
    parser.process(application);
    about.processCommandLine(&parser);

    KSignalHandler::self()->watchSignal(SIGINT);
    KSignalHandler::self()->watchSignal(SIGTERM);
    QObject::connect(KSignalHandler::self(), &KSignalHandler::signalReceived, &application, [](int) {
        QCoreApplication::exit(0);
    });

    auto config = ServerConfig::self();

    auto parserValueWithDefault = [&parser](QAnyStringView option, auto defaultValue) {
        auto optionString = option.toString();
        if (parser.isSet(optionString)) {
            return QVariant(parser.value(optionString)).value<decltype(defaultValue)>();
        } else {
            return defaultValue;
        }
    };

    QHostAddress address = QHostAddress::Any;
    if (parser.isSet(kOptionAddress)) {
        address = QHostAddress(parser.value(kOptionAddress));
    }
    auto port = parserValueWithDefault(kOptionPort, config->listenPort());
    auto certificate = std::filesystem::path(parserValueWithDefault(kOptionCertificate, config->certificate()).toStdString());
    auto certificateKey = std::filesystem::path(parserValueWithDefault(kOptionCertificateKey, config->certificateKey()).toStdString());

    const QString remoteId = parser.isSet(kOptionRemoteId) ? parser.value(kOptionRemoteId) : qEnvironmentVariable(kEnvRemoteId);
    const bool handover = parser.isSet(kOptionHandover) || !remoteId.isEmpty();
    if (handover && remoteId.isEmpty()) {
        qWarning() << "--handover requires a --remote-id.";
        return -1;
    }

    KRdp::Server server(nullptr);

    server.setAddress(address);
    server.setPort(port);

    server.setTlsCertificate(certificate);
    server.setTlsCertificateKey(certificateKey);

    // Use parsed username/pw if set
    if (!handover && parser.isSet(kOptionUsername)) {
        KRdp::User user;
        user.name = parser.value(kOptionUsername);
        user.password = parser.value(kOptionPassword);
        server.addUser(user);
    }
    // Otherwise use KCM username list
    else if (!handover) {
        const bool pamNeeded = config->systemUserEnabled() || !config->allowedSystemUsers().isEmpty() || !config->allowedSystemGroups().isEmpty();
        server.setUsePAMAuthentication(pamNeeded);
        server.setAllowedSystemUsers(config->allowedSystemUsers());
        server.setAllowedSystemGroups(config->allowedSystemGroups());

        const auto users = config->users();
        for (const auto &userName : users) {
            const auto readJob = new QKeychain::ReadPasswordJob(kKeychainService.toString());
            readJob->setKey(QLatin1StringView(userName.toLatin1()));
            QObject::connect(readJob, &QKeychain::ReadPasswordJob::finished, &server, [userName, readJob, &server]() {
                KRdp::User user;
                if (readJob->error() != QKeychain::Error::NoError) {
                    qWarning() << "requestPassword: Failed to read password of " << userName << " because of error: " << readJob->error();
                    return;
                }
                user.name = userName;
                user.password = readJob->textData();
                server.addUser(user);
            });
            readJob->start();
        }
        if (users.isEmpty() && !pamNeeded) {
            qWarning() << "No users configured for login. Either pass a username/password or configure users using kcm_krdp.";
            return -1;
        }
    }
    // In handover mode the intended user is added by the HandoverManager when
    // the dispatcher answers, so do not load any users from the configuration.
    else {
        server.setUsePAMAuthentication(false);
    }

    const auto sessionType =
#ifdef WITH_PLASMA_SESSION
        (parser.isSet(kOptionPlasma) || handover) ? SessionController::SessionType::Plasma :
#endif
                                                  SessionController::SessionType::Portal;
    const QString xdgSeat = qEnvironmentVariable(kEnvXdgSeat);
    const bool isHeadlessRemoteSession = qEnvironmentVariableIntValue(kEnvIsRemote) == kEnvEnabledValue
        || xdgSeat.startsWith(kRemoteSeatUnderscorePrefix, Qt::CaseInsensitive) || xdgSeat.startsWith(kRemoteSeatHyphenPrefix, Qt::CaseInsensitive);

    SessionController controller(&server, sessionType);
    controller.setHandoverMode(handover);
    if (parser.isSet(kOptionVirtualMonitor)) {
        const QString vmData = parser.value(kOptionVirtualMonitor);
        const auto match = kVirtualMonitorPattern.match(vmData);
        if (!match.hasMatch()) {
            qWarning() << "failed to parse" << vmData << ".  Should be WIDTHxHEIGHT@SCALE";
            return 1;
        }
        controller.setVirtualMonitor({vmData, {match.capturedView(1).toInt(), match.capturedView(2).toInt()}, match.capturedView(3).toDouble()});
    } else if (parser.isSet(kOptionMonitor)) {
        controller.setMonitorIndex(parser.value(kOptionMonitor).toInt());
    } else {
        controller.setMonitorIndex(std::nullopt);
    }
    controller.setQuality(parserValueWithDefault(kOptionQuality, config->quality()));
    controller.setAdaptiveQuality((parser.isSet(kOptionAdaptiveQuality) || config->adaptiveQuality()) && !parser.isSet(kOptionStaticQuality));
    if (parser.isSet(kOptionMode)) {
        const auto mode = parseOperationMode(parser.value(kOptionMode));
        if (!mode) {
            qWarning() << "failed to parse operation mode" << parser.value(kOptionMode) << ". Expected RemoteAccess, SharedAccess, or AdditionalDisplay";
            return 1;
        }
        controller.setOperationMode(*mode);
    } else if (handover) {
        // User handover sessions (both headless remote-first and hot-swapped
        // from seat0) create a dedicated virtual output for the RDP client that
        // is automatically removed when krdpserver stops on local console takeover.
        controller.setOperationMode(SessionController::OperationMode::RemoteAccess);
    } else {
        controller.setOperationMode(config->exclusiveMode() ? SessionController::OperationMode::RemoteAccess : SessionController::OperationMode::SharedAccess);
    }

    if (handover) {
        const bool isGreeterSession = qEnvironmentVariable(kEnvXdgSessionClass) == kGreeterSessionClass;
        bool terminateOnDisconnect = isHeadlessRemoteSession && !isGreeterSession;
        if (terminateOnDisconnect) {
            KSharedConfig::Ptr dispatcherConfig = KSharedConfig::openConfig(kDispatcherConfigFileName.toString());
            KConfigGroup generalGroup = dispatcherConfig->group(kGeneralConfigGroup.toString());
            terminateOnDisconnect = generalGroup.readEntry(kTerminateOnDisconnectKey, true);
        }
        if (parser.isSet(kOptionNoTerminateOnDisconnect)) {
            terminateOnDisconnect = false;
        } else if (parser.isSet(kOptionTerminateOnDisconnect)) {
            terminateOnDisconnect = true;
        }

        auto handoverManager = std::make_unique<HandoverManager>(remoteId, &server, terminateOnDisconnect);
        handoverManager->start();
        return application.exec();
    }

    if (!server.start()) {
        return -1;
    }

    return application.exec();
}
