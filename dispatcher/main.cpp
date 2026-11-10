// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include <csignal>
#include <filesystem>

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QProcess>

#include <KAboutData>
#include <KCrash>
#include <KSharedConfig>
#include <KSignalHandler>

#include "Dispatcher.h"
#include "krdp_version.h"
#include "krdpdispatchersettings.h"

using namespace Qt::StringLiterals;

namespace
{
inline constexpr auto EnvHome = "HOME";
inline constexpr auto FallbackHomePath = "/";

inline constexpr auto AppName = "krdp-dispatcher"_L1;
inline constexpr auto AppDisplayName = "KRDP Dispatcher"_L1;
inline constexpr auto DesktopFileName = "org.kde.krdp.dispatcher"_L1;

inline constexpr auto OptionAddress = "address"_L1;
inline constexpr auto OptionPort = "port"_L1;
inline constexpr auto OptionCertificate = "certificate"_L1;
inline constexpr auto OptionCertificateKey = "certificate-key"_L1;

inline constexpr auto DefaultAddress = "0.0.0.0"_L1;
inline constexpr auto DefaultPort = "3389"_L1;
inline constexpr auto DefaultCertificate = "server.crt"_L1;
inline constexpr auto DefaultCertificateKey = "server.key"_L1;

inline constexpr auto AppDescription =
    "An RDP dispatcher that redirects remote clients to the session that should serve them.\nNote that a valid TLS certificate and key is needed."_L1;
inline constexpr auto OptionAddressDesc = "The address to listen on for connections. Defaults to 0.0.0.0"_L1;
inline constexpr auto OptionPortDesc = "The port to use for connections. Defaults to 3389."_L1;
inline constexpr auto OptionCertificateDesc = "The TLS certificate file to use."_L1;
inline constexpr auto OptionCertificateKeyDesc = "The TLS certificate key to use."_L1;

inline constexpr auto OpenSslBinary = "openssl"_L1;
inline constexpr auto OpenSslReqCmd = "req"_L1;
inline constexpr auto OpenSslNodesFlag = "-nodes"_L1;
inline constexpr auto OpenSslX509Flag = "-x509"_L1;
inline constexpr auto OpenSslNewKeyFlag = "-newkey"_L1;
inline constexpr auto OpenSslRsa2048 = "rsa:2048"_L1;
inline constexpr auto OpenSslKeyOutFlag = "-keyout"_L1;
inline constexpr auto OpenSslOutFlag = "-out"_L1;
inline constexpr auto OpenSslDaysFlag = "-days"_L1;
inline constexpr auto OpenSslValidityDays = "3650"_L1;
inline constexpr auto OpenSslSubjFlag = "-subj"_L1;
inline constexpr auto OpenSslSubjValue = "/CN=krdp-dispatcher"_L1;

bool generateCertificateIfMissing(const std::filesystem::path &cert, const std::filesystem::path &key)
{
    if (std::filesystem::exists(cert) && std::filesystem::exists(key)) {
        return true;
    }
    const auto parent = cert.parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::error_code ec;
        std::filesystem::create_directories(parent, ec);
    }
    const int exitCode = QProcess::execute(OpenSslBinary.toString(),
                                           {OpenSslReqCmd.toString(),
                                            OpenSslNodesFlag.toString(),
                                            OpenSslX509Flag.toString(),
                                            OpenSslNewKeyFlag.toString(),
                                            OpenSslRsa2048.toString(),
                                            OpenSslKeyOutFlag.toString(),
                                            QString::fromStdString(key.string()),
                                            OpenSslOutFlag.toString(),
                                            QString::fromStdString(cert.string()),
                                            OpenSslDaysFlag.toString(),
                                            OpenSslValidityDays.toString(),
                                            OpenSslSubjFlag.toString(),
                                            OpenSslSubjValue.toString()});
    if (exitCode == 0) {
        std::error_code ec;
        std::filesystem::permissions(key, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, ec);
        std::filesystem::permissions(cert,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write | std::filesystem::perms::group_read
                                         | std::filesystem::perms::others_read,
                                     std::filesystem::perm_options::replace,
                                     ec);
        return true;
    }
    return false;
}
}

int main(int argc, char **argv)
{
    // FreeRDP refuses to create a peer context without HOME, and system
    // services do not get one. The systemd unit sets it; fall back to the
    // filesystem root so a manually started dispatcher works as well.
    if (qEnvironmentVariableIsEmpty(EnvHome)) {
        qputenv(EnvHome, FallbackHomePath);
    }

    QCoreApplication application{argc, argv};
    application.setApplicationName(AppName.toString());

    KAboutData about(AppName.toString(), AppDisplayName.toString(), QStringLiteral(KRdp_VERSION_STRING));
    about.setDesktopFileName(DesktopFileName.toString());
    KAboutData::setApplicationData(about);

    KCrash::initialize();

    QCommandLineParser parser;
    parser.setApplicationDescription(AppDescription.toString());
    parser.addOptions({
        {OptionAddress.toString(), OptionAddressDesc.toString(), OptionAddress.toString()},
        {OptionPort.toString(), OptionPortDesc.toString(), OptionPort.toString(), DefaultPort.toString()},
        {OptionCertificate.toString(), OptionCertificateDesc.toString(), OptionCertificate.toString(), DefaultCertificate.toString()},
        {OptionCertificateKey.toString(), OptionCertificateKeyDesc.toString(), OptionCertificateKey.toString(), DefaultCertificateKey.toString()},
    });
    about.setupCommandLine(&parser);
    parser.process(application);
    about.processCommandLine(&parser);

    KSignalHandler::self()->watchSignal(SIGINT);
    KSignalHandler::self()->watchSignal(SIGTERM);
    QObject::connect(KSignalHandler::self(), &KSignalHandler::signalReceived, &application, [](int) {
        QCoreApplication::exit(0);
    });

    auto config = DispatcherConfig::self();

    auto parserValueWithDefault = [&parser](QAnyStringView option, auto defaultValue) {
        auto optionString = option.toString();
        if (parser.isSet(optionString)) {
            return QVariant(parser.value(optionString)).value<decltype(defaultValue)>();
        } else {
            return defaultValue;
        }
    };

    QHostAddress address = QHostAddress(parserValueWithDefault(OptionAddress, config->listenAddress()));
    auto port = parserValueWithDefault(OptionPort, config->listenPort());
    auto certificate = std::filesystem::path(parserValueWithDefault(OptionCertificate, config->certificate()).toStdString());
    auto certificateKey = std::filesystem::path(parserValueWithDefault(OptionCertificateKey, config->certificateKey()).toStdString());

    if (config->autogenerateCertificates() && (!std::filesystem::exists(certificate) || !std::filesystem::exists(certificateKey))) {
        generateCertificateIfMissing(certificate, certificateKey);
    }

    KRdp::Dispatcher dispatcher;

    dispatcher.setAddress(address);
    dispatcher.setPort(port);
    dispatcher.setSystemCertificate(certificate);
    dispatcher.setSystemCertificateKey(certificateKey);

    if (!dispatcher.start()) {
        return -1;
    }

    return application.exec();
}
