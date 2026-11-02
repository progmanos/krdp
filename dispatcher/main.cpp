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
    const int exitCode = QProcess::execute(QStringLiteral("openssl"),
                                           {QStringLiteral("req"),
                                            QStringLiteral("-nodes"),
                                            QStringLiteral("-x509"),
                                            QStringLiteral("-newkey"),
                                            QStringLiteral("rsa:2048"),
                                            QStringLiteral("-keyout"),
                                            QString::fromStdString(key.string()),
                                            QStringLiteral("-out"),
                                            QString::fromStdString(cert.string()),
                                            QStringLiteral("-days"),
                                            QStringLiteral("3650"),
                                            QStringLiteral("-subj"),
                                            QStringLiteral("/CN=krdp-dispatcher")});
    return exitCode == 0;
}
}

int main(int argc, char **argv)
{
    // FreeRDP refuses to create a peer context without HOME, and system
    // services do not get one. The systemd unit sets it; fall back to the
    // filesystem root so a manually started dispatcher works as well.
    if (qEnvironmentVariableIsEmpty("HOME")) {
        qputenv("HOME", "/");
    }

    QCoreApplication application{argc, argv};
    application.setApplicationName(u"krdp-dispatcher"_s);

    KAboutData about(u"krdp-dispatcher"_s, u"KRDP Dispatcher"_s, QStringLiteral(KRdp_VERSION_STRING));
    about.setDesktopFileName(u"org.kde.krdp.dispatcher"_s);
    KAboutData::setApplicationData(about);

    KCrash::initialize();

    QCommandLineParser parser;
    parser.setApplicationDescription(
        u"An RDP dispatcher that redirects remote clients to the session that should serve them.\nNote that a valid TLS certificate and key is needed."_s);
    parser.addOptions({
        {u"address"_s, u"The address to listen on for connections. Defaults to 0.0.0.0"_s, u"address"_s},
        {u"port"_s, u"The port to use for connections. Defaults to 3389."_s, u"port"_s, u"3389"_s},
        {u"certificate"_s, u"The TLS certificate file to use."_s, u"certificate"_s, u"server.crt"_s},
        {u"certificate-key"_s, u"The TLS certificate key to use."_s, u"certificate-key"_s, u"server.key"_s},
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

    QHostAddress address = QHostAddress(parserValueWithDefault(u"address", config->listenAddress()));
    auto port = parserValueWithDefault(u"port", config->listenPort());
    auto certificate = std::filesystem::path(parserValueWithDefault(u"certificate", config->certificate()).toStdString());
    auto certificateKey = std::filesystem::path(parserValueWithDefault(u"certificate-key", config->certificateKey()).toStdString());

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
