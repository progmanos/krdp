// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <memory>
#include <thread>

#include <QObject>

#include <freerdp/freerdp.h>

#include "Redirection.h"
#include "krdp_export.h"

namespace KRdp
{

class InputHandler;
class Server;
class VideoStream;
class VideoStreamSurface;
class Cursor;
class NetworkDetection;
class Clipboard;
class DisplayControl;

/**
 * An RDP session.
 *
 * This represents an RDP session, that is, a connection between an RDP client
 * and the server. It primarily takes care of the RDP communication side of
 * things.
 *
 * Note that this class starts its own thread for performing the actual
 * communication.
 */
class KRDP_EXPORT RdpConnection : public QObject
{
    Q_OBJECT

public:
    /**
     * Session state.
     */
    enum class State {
        Initial,
        Starting,
        Running,
        Activated,
        Streaming,
        Closed,
    };

    /**
     * Reasons for closing the stream.
     */
    enum class CloseReason {
        None, ///< No particular reason, e.g. closing due to normal operation
              ///  like client disconnect.
        VideoInitFailed, ///< VideoStream failed to initialize.
        UserLogoff, ///< User logged off from the session.
        ReplacedByOtherConnection, ///< Another client or local login took over the session.
    };

    /**
     * Constructor.
     *
     * \param server The KRdp::Server instance this session is part of.
     * \param socketHandle A file handle to the socket this session should use
     *                     for communication.
     */
    explicit RdpConnection(Server *server, qintptr socketHandle);
    ~RdpConnection() override;

    /**
     * The current session state.
     */
    State state() const;
    Q_SIGNAL void stateChanged(State newState);

    /**
     * The username of the authenticated client.
     */
    QString username() const;

    /**
     * The IP address / host of the connected client.
     */
    QString clientAddress() const;

    /**
     * Close the connection
     *
     * \param reason The reason to close the connection. May set error state if
     *               it is something different than CloseReason::None.
     */
    void close(CloseReason reason = CloseReason::None);

    /**
     * Ask the client to disconnect and reconnect to a different KRdp instance.
     *
     * A ServerRedirection PDU is sent to the client, containing a routing
     * token and one-time credentials so it can reconnect to the destination
     * session. This is used when a login session hands over a remote client to
     * the user session.
     *
     * The PDU is sent from the session's run thread, so this method is safe to
     * call from any thread.
     *
     * \param info The routing token and credentials for the destination.
     */
    void sendServerRedirection(const RedirectionInfo &info);

    /**
     * The InputHandler instance associated with this session.
     */
    InputHandler *inputHandler() const;
    /**
     * The VideoStream instance associated with this session.
     */
    VideoStream *videoStream() const;
    /**
     * The Cursor instance associated with this session.
     */
    Cursor *cursor() const;

    Clipboard *clipboard() const;

    DisplayControl *displayControl() const;

    NetworkDetection *networkDetection() const;

private:
    friend BOOL peerCapabilities(freerdp_peer *);
    friend BOOL peerActivate(freerdp_peer *);
    friend BOOL peerPostConnect(freerdp_peer *);
    friend BOOL suppressOutput(rdpContext *, uint8_t, const RECTANGLE_16 *);

    friend class Cursor;
    friend class VideoStream;
    friend class VideoStreamSurface;
    friend class NetworkDetection;
    friend class Clipboard;
    friend class DisplayControl;

    void setState(State newState);
    void initialize();
    void run(std::stop_token stopToken);

    freerdp_peer *rdpPeer() const;
    rdpContext *rdpPeerContext() const;

    bool onCapabilities();
    bool onActivate();
    bool onPostConnect();
    bool onClose();
    bool onSuppressOutput(uint8_t allow);
    bool sendServerRedirectionOnRunThread(const RedirectionInfo &info);

    class Private;
    const std::unique_ptr<Private> d;
};

}
