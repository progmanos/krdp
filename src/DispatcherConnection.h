// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <memory>
#include <thread>

#include <QObject>

#include <freerdp/freerdp.h>

#include "krdp_export.h"

namespace KRdp
{

class Dispatcher;
struct RedirectionInfo;

/**
 * The initial RDP connection of a remote client, held by the Dispatcher.
 *
 * The connection is completed with TLS using the system certificate and then
 * the client is redirected to the session that actually wants to serve it.
 * A separate thread performs the actual FreeRDP communication, so this class
 * is safe to use from any thread.
 */
class KRDP_EXPORT DispatcherConnection : public QObject
{
    Q_OBJECT

public:
    DispatcherConnection(Dispatcher *dispatcher, qintptr socketHandle);
    ~DispatcherConnection() override;

    /**
     * Ask the communication thread to finish. Safe to call from any thread.
     */
    void requestStop();

    /**
     * Ask the client to disconnect and reconnect with the given routing token.
     *
     * The ServerRedirection PDU is sent from the communication thread once the
     * client has been fully connected, so this method is safe to call from
     * any thread.
     */
    void sendServerRedirection(const RedirectionInfo &info);

    /**
     * Emitted once the client has completed the initial RDP handshake and is
     * ready to receive a ServerRedirection PDU.
     */
    Q_SIGNAL void connected();

    /**
     * Emitted when the communication thread has finished and the connection is
     * torn down, for any reason.
     */
    Q_SIGNAL void closed();

private:
    friend BOOL dispatcherPeerPostConnect(freerdp_peer *);
    friend BOOL dispatcherPeerActivate(freerdp_peer *);

    void initialize();
    void run(std::stop_token stopToken);
    void onPeerConnected();
    void onPeerActivated();
    bool sendServerRedirectionOnRunThread(const RedirectionInfo &info);

    class Private;
    const std::unique_ptr<Private> d;
};

}