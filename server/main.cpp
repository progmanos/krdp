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

static std::optional<SessionController::OperationMode> parseOperationMode(QAnyStringView value)
{
    if (value == u"RemoteAccess"_s) {
        return SessionController::OperationMode::RemoteAccess;
    }
    if (value == u"SharedAccess"_s) {
        return SessionController::OperationMode::SharedAccess;
    }
    if (value == u"AdditionalDisplay"_s) {
        return SessionController::OperationMode::AdditionalDisplay;
    }

    return std::nullopt;
}

int main(int argc, char **argv)
{
    QApplication application{argc, argv};
    application.setApplicationName(u"krdp-server"_s);
    application.setApplicationDisplayName(u"KRDP Server"_s);

    KAboutData about(u"krdp-server"_s, u"KRDP Server"_s, QStringLiteral(KRdp_VERSION_STRING));
    about.setDesktopFileName(u"org.kde.krdpserver"_s);
    KAboutData::setApplicationData(about);

    KCrash::initialize();

    QCommandLineParser parser;
    parser.setApplicationDescription(
        u"An RDP server that exposes the current desktop session over the RDP protocol.\nNote that a valid TLS certificate and key is needed. If not provided, a temporary certificate will be generated."_s);
    parser.addOptions({
        {{u"u"_s, u"username"_s}, u"The username to use for login"_s, u"username"_s},
        {{u"p"_s, u"password"_s}, u"The password to use for login. Requires username to be passed as well."_s, u"password"_s},
        {u"address"_s, u"The address to listen on for connections. Defaults to 0.0.0.0"_s, u"address"_s},
        {u"port"_s, u"The port to use for connections. Defaults to 3389."_s, u"port"_s, u"3389"_s},
        {u"certificate"_s, u"The TLS certificate file to use."_s, u"certificate"_s, u"server.crt"_s},
        {u"certificate-key"_s, u"The TLS certificate key to use."_s, u"certificate-key"_s, u"server.key"_s},
        {u"monitor"_s, u"The index of the monitor to use when streaming."_s, u"monitor"_s, u"-1"_s},
        {u"virtual-monitor"_s,
         u"Creates a new virtual output to connect to (WIDTHxHEIGHT@SCALE, e.g. 1920x1080@1). Incompatible with --monitor."_s,
         u"data"_s,
         u"1920x1080@1"_s},
        {u"mode"_s, u"The operation mode to use: RemoteAccess, SharedAccess, or AdditionalDisplay."_s, u"mode"_s},
        {u"quality"_s,
         u"Encoding quality of the stream, from 0 (lowest) to 100 (highest). With adaptive quality (the default) this is the upper bound; with --static-quality it is the fixed quality."_s,
         u"quality"_s},
        {u"adaptive-quality"_s,
         u"Adjust the encoding quality at runtime based on the client's network conditions, up to --quality. On by default; only matters if disabled in the configuration."_s},
        {u"static-quality"_s, u"Pin the encoding quality at --quality instead of adapting it to the client's network conditions."_s},
        {u"handover"_s, u"Run as the destination of a remote login handover with the system KRdp dispatcher, instead of listening for connections."_s},
        {u"remote-id"_s, u"The remote id of the client to serve. Must be used with --handover."_s, u"remote-id"_s},
        {u"terminate-on-disconnect"_s, u"Terminate the user session when the client disconnects (default in handover mode)."_s},
        {u"no-terminate-on-disconnect"_s, u"Do not terminate the user session when the client disconnects."_s},
#ifdef WITH_PLASMA_SESSION
        {u"plasma"_s, u"Use Plasma protocols instead of XDP"_s},
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
    if (parser.isSet(u"address"_s)) {
        address = QHostAddress(parser.value(u"address"_s));
    }
    auto port = parserValueWithDefault(u"port", config->listenPort());
    auto certificate = std::filesystem::path(parserValueWithDefault(u"certificate", config->certificate()).toStdString());
    auto certificateKey = std::filesystem::path(parserValueWithDefault(u"certificate-key", config->certificateKey()).toStdString());

    const QString remoteId = parser.isSet(u"remote-id"_s) ? parser.value(u"remote-id"_s) : qEnvironmentVariable("PLASMALOGIN_REMOTE_ID");
    const bool handover = parser.isSet(u"handover"_s) || !remoteId.isEmpty();
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
    if (!handover && parser.isSet(u"username"_s)) {
        KRdp::User user;
        user.name = parser.value(u"username"_s);
        user.password = parser.value(u"password"_s);
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
            const auto readJob = new QKeychain::ReadPasswordJob(QLatin1StringView("KRDP"));
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
        (parser.isSet(u"plasma"_s) || handover) ? SessionController::SessionType::Plasma :
#endif
                                                SessionController::SessionType::Portal;
    SessionController controller(&server, sessionType);
    if (parser.isSet(u"virtual-monitor"_s)) {
        const QString vmData = parser.value(u"virtual-monitor"_s);
        const QRegularExpression rx(uR"((\d+)x(\d+)@([\d.]+))"_s);
        const auto match = rx.match(vmData);
        if (!match.hasMatch()) {
            qWarning() << "failed to parse" << vmData << ".  Should be WIDTHxHEIGHT@SCALE";
            return 1;
        }
        controller.setVirtualMonitor({vmData, {match.capturedView(1).toInt(), match.capturedView(2).toInt()}, match.capturedView(3).toDouble()});
    } else if (parser.isSet(u"monitor"_s)) {
        controller.setMonitorIndex(parser.value(u"monitor"_s).toInt());
    } else if (handover) {
        // Headless remote sessions already run KWin with --virtual, so stream
        // the primary virtual output directly.
        constexpr int kPrimaryMonitorIndex = 0;
        controller.setMonitorIndex(kPrimaryMonitorIndex);
    } else {
        controller.setMonitorIndex(std::nullopt);
    }
    controller.setQuality(parserValueWithDefault(u"quality", config->quality()));
    controller.setAdaptiveQuality((parser.isSet(u"adaptive-quality"_s) || config->adaptiveQuality()) && !parser.isSet(u"static-quality"_s));
    if (parser.isSet(u"mode"_s)) {
        const auto mode = parseOperationMode(parser.value(u"mode"_s));
        if (!mode) {
            qWarning() << "failed to parse operation mode" << parser.value(u"mode"_s) << ". Expected RemoteAccess, SharedAccess, or AdditionalDisplay";
            return 1;
        }
        controller.setOperationMode(*mode);
    } else {
        controller.setOperationMode(config->exclusiveMode() ? SessionController::OperationMode::RemoteAccess : SessionController::OperationMode::SharedAccess);
    }

    if (handover) {
        bool terminateOnDisconnect = true;
        {
            KSharedConfig::Ptr dispatcherConfig = KSharedConfig::openConfig(QStringLiteral("krdpdispatcherrc"));
            KConfigGroup generalGroup = dispatcherConfig->group(QStringLiteral("General"));
            terminateOnDisconnect = generalGroup.readEntry("TerminateOnDisconnect", true);
        }
        if (parser.isSet(u"no-terminate-on-disconnect"_s)) {
            terminateOnDisconnect = false;
        } else if (parser.isSet(u"terminate-on-disconnect"_s)) {
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
