// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <filesystem>
#include <memory>

#include <QDBusContext>
#include <QDBusUnixFileDescriptor>
#include <QTcpServer>

#include <freerdp/settings.h>

#include "krdp_export.h"

namespace KRdp
{

class DispatcherConnection;

/**
 * The KRdp Dispatcher.
 *
 * This is the system daemon that owns the RDP listener. Remote clients
 * initially connect to it, get authenticated, and are then handed over to the
 * session that should actually serve them: first to the greeter (login
 * screen) and then to the user session. Each handover happens via RDP Server
 * Redirection followed by a reconnect of the client with the routing token.
 *
 * Session daemons communicate with the dispatcher over the system D-Bus via
 * the @c org.kde.krdp.Dispatcher interface:
 *
 * - The session that wants to take over the client calls @c StartHandover()
 *   with one-time credentials and receives the certificate/key pair it should
 *   use.
 * - If the dispatcher still holds the client it redirects it itself. If
 *   another session already holds the client, a @c RedirectClient signal is
 *   sent to that session so it performs the redirection.
 * - Once the client has reconnected with the routing token, the dispatcher
 *   emits @c TakeClientReady to the waiting session, which then calls @c
 *   TakeClient() to receive the socket as a file descriptor.
 *
 * The dispatcher itself must be reachable from the client, so it listens on
 * the configured address and port (default localhost, port 3389).
 */
class KRDP_EXPORT Dispatcher : public QTcpServer, protected QDBusContext
{
    Q_OBJECT

public:
    explicit Dispatcher(QObject *parent = nullptr);
    ~Dispatcher() override;

    /**
     * The host address to listen on.
     *
     * Set this to an appropriate address for the dispatcher to listen on.
     * Common options are `0.0.0.0` to listen on all interfaces or `127.0.0.1`
     * to only accept local connections. By default this is QHostAddress::LocalHost.
     */
    QHostAddress address() const;
    void setAddress(const QHostAddress &newAddress);

    /**
     * The port to listen on. By default this is set to 3389, the standard RDP
     * port.
     */
    quint16 port() const;
    void setPort(quint16 newPort);

    /**
     * The TLS certificate the dispatcher uses for the initial connection of a
     * client, before it is redirected to its actual session.
     */
    std::filesystem::path systemCertificate() const;
    void setSystemCertificate(const std::filesystem::path &path);

    /**
     * The private key matching systemCertificate().
     */
    std::filesystem::path systemCertificateKey() const;
    void setSystemCertificateKey(const std::filesystem::path &path);

    /**
     * Initialise the dispatcher without listening yet. Creates the shared
     * FreeRDP settings object used by all connections.
     */
    bool initialize();

    /**
     * Register the D-Bus service and start listening for incoming connections.
     */
    bool start();

    /**
     * Unregister the D-Bus service and stop listening.
     */
    void stop();

    /**
     * D-Bus method @c StartHandover, see org.kde.krdp.Dispatcher.xml.
     *
     * Called by the generated @c DispatcherAdaptor. Returns the PEM
     * certificate the destination session should use and fills \p
     * certificateKey with the matching private key.
     */
    QString StartHandover(const QString &remoteId, const QString &username, const QString &password, QString &certificateKey);

    /**
     * D-Bus method @c TakeClient, see org.kde.krdp.Dispatcher.xml.
     *
     * Returns the socket of a reconnected client as a file descriptor.
     */
    QDBusUnixFileDescriptor TakeClient(const QString &remoteId);

protected:
    /**
     * Overridden from QTcpServer.
     */
    void incomingConnection(qintptr handle) override;

private:
    friend class DispatcherConnection;

    void handleNewConnection(qintptr handle);
    void handleRedirectedConnection(const QString &remoteId, qintptr handle);
    void tryPeek(qintptr handle);
    void cleanupPeek(qintptr handle);

    void emitTakeClientReady(const QString &remoteId);
    void emitRedirectClient(const QString &destination, const QString &remoteId, const QString &username, const QString &password);
    void emitClientConnected(const QString &remoteId);
    void emitClientDisconnected(const QString &remoteId);

    rdp_settings *rdpSettings() const;

    class Private;
    const std::unique_ptr<Private> d;
};

}