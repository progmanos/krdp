// SPDX-FileCopyrightText: 2023 Arjen Hiemstra <ahiemstra@heimr.nl>
//
// This file is roughly based on grd-session-rdp.c from gnome-remote-desktop,
// which is:
//
// SPDX-FileCopyrightText: 2020-2023 Pascal Nowack
//
// SPDX-License-Identifier: GPL-2.0-or-later

#include "RdpConnection.h"

#include <mutex>
#include <optional>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#include <QFile>
#include <QHostAddress>
#include <QTcpSocket>
#include <QTemporaryFile>
#include <QThread>

#include <freerdp/channels/wtsvc.h>
#include <freerdp/freerdp.h>
#include <freerdp/server/cliprdr.h>

#include <freerdp/channels/drdynvc.h>

#include "AbstractSession.h"
#include "Clipboard.h"
#include "Cursor.h"
#include "DisplayControl.h"
#include "InputHandler.h"
#include "NetworkDetection.h"
#include "PeerContext_p.h"
#include "Redirection.h"
#include "SamFile.h"
#include "Server.h"
#include "VideoStream.h"

#include <KUser>

#include "krdp_logging.h"

namespace KRdp
{

#include <security/pam_appl.h>

typedef struct {
    QByteArray user;
    QByteArray password;
} RDPConnectionAuthData;

typedef struct {
    pam_handle_t *handle;
    struct pam_conv pamc;
    RDPConnectionAuthData appdata;
} RdpConnectionPamHandle;

static int pam_conv(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
    int pam_status = PAM_CONV_ERR;
    RDPConnectionAuthData *appdata = NULL;
    struct pam_response *response = NULL;
    WINPR_ASSERT(num_msg >= 0);
    appdata = (RDPConnectionAuthData *)appdata_ptr;
    WINPR_ASSERT(appdata);

    if (!(response = (struct pam_response *)calloc((size_t)num_msg, sizeof(struct pam_response))))
        return PAM_BUF_ERR;

    for (int index = 0; index < num_msg; index++) {
        switch (msg[index]->msg_style) {
        case PAM_PROMPT_ECHO_ON:
            response[index].resp = _strdup(appdata->user.constData());

            if (!response[index].resp)
                goto out_fail;

            response[index].resp_retcode = PAM_SUCCESS;
            break;

        case PAM_PROMPT_ECHO_OFF:
            response[index].resp = _strdup(appdata->password.constData());

            if (!response[index].resp)
                goto out_fail;

            response[index].resp_retcode = PAM_SUCCESS;
            break;

        default:
            pam_status = PAM_CONV_ERR;
            goto out_fail;
        }
    }

    *resp = response;
    return PAM_SUCCESS;
out_fail:

    for (int index = 0; index < num_msg; ++index) {
        if (response[index].resp) {
            memset(response[index].resp, 0, strlen(response[index].resp));
            free(response[index].resp);
        }
    }

    memset(response, 0, sizeof(struct pam_response) * (size_t)num_msg);
    free(response);
    *resp = NULL;
    return pam_status;
}

static int pamAuthenticate(const QString &user, const QString &password)
{
    int pam_status = 0;
    RdpConnectionPamHandle info = {0};

    info.appdata.user = user.toLatin1();
    info.appdata.password = password.toLatin1();
    info.pamc.conv = &pam_conv;
    info.pamc.appdata_ptr = &info.appdata;

    pam_status = pam_start("login", 0, &info.pamc, &info.handle);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_start failure:" << pam_strerror(info.handle, pam_status);
        return -1;
    }

    pam_status = pam_authenticate(info.handle, 0);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_authenticate failure:" << pam_strerror(info.handle, pam_status);
        return -1;
    }

    pam_status = pam_acct_mgmt(info.handle, 0);

    if (pam_status != PAM_SUCCESS) {
        qWarning() << "pam_acct_mgmt failure:" << pam_strerror(info.handle, pam_status);
        return -1;
    }

    return 1;
}

/**
 * FreeRDP callback for the capabilities event.
 */
BOOL peerCapabilities(freerdp_peer *peer)
{
    auto context = contextForPeer(peer);
    if (context->connection->onCapabilities()) {
        return TRUE;
    }

    return FALSE;
}

/**
 * FreeRDP callback for the post connect event.
 */
BOOL peerPostConnect(freerdp_peer *peer)
{
    auto context = contextForPeer(peer);
    if (context->connection->onPostConnect()) {
        return TRUE;
    }

    return FALSE;
}

/**
 * FreeRDP callback for the activate event.
 */
BOOL peerActivate(freerdp_peer *peer)
{
    auto context = reinterpret_cast<PeerContext *>(peer->context);
    if (context->connection->onActivate()) {
        return TRUE;
    }

    return FALSE;
}

BOOL suppressOutput(rdpContext *context, uint8_t allow, const RECTANGLE_16 *)
{
    auto peerContext = reinterpret_cast<PeerContext *>(context);
    if (peerContext->connection->onSuppressOutput(allow)) {
        return TRUE;
    }

    return FALSE;
}

class KRDP_NO_EXPORT RdpConnection::Private
{
public:
    Server *server = nullptr;

    State state = State::Initial;
    bool qualitySeeded = false;

    qintptr socketHandle;

    std::unique_ptr<InputHandler> inputHandler;
    std::unique_ptr<VideoStream> videoStream;
    std::unique_ptr<Cursor> cursor;
    std::unique_ptr<NetworkDetection> networkDetection;
    std::unique_ptr<Clipboard> clipboard;
    std::unique_ptr<DisplayControl> displayControl;

    freerdp_peer *peer = nullptr;

    std::jthread thread;

    // Manual-reset event the run thread waits on alongside the peer transport
    // handles. Signalling it wakes the thread for teardown without any protocol
    // I/O on the peer from the calling thread.
    HANDLE stopEvent = nullptr;

    // Auto-reset event used to ask the run thread to send a ServerRedirection
    // PDU. Together with pendingRedirection it marshals redirection requests
    // from any thread onto the thread that owns the peer and its transport.
    HANDLE redirectionEvent = nullptr;
    std::mutex redirectionMutex;
    std::optional<RedirectionInfo> pendingRedirection;

    // Ask the run thread to finish, from any thread. It owns the peer and closes
    // it as it exits, so callers never touch the peer themselves.
    void requestStop()
    {
        thread.request_stop();
        if (stopEvent) {
            SetEvent(stopEvent);
        }
    }

    QTemporaryFile samFile;
    QString username;
    QString clientAddress;
};

RdpConnection::RdpConnection(Server *server, qintptr socketHandle)
    : QObject(nullptr)
    , d(std::make_unique<Private>())
{
    d->server = server;
    d->socketHandle = socketHandle;

    d->inputHandler = std::make_unique<InputHandler>(this);
    d->videoStream = std::make_unique<VideoStream>(this);
    connect(d->videoStream.get(), &VideoStream::closed, this, [this]() {
        if (d->state == State::Running || d->state == State::Streaming) {
            qCDebug(KRDP) << "Video stream closed, closing session";
            d->requestStop();
        }
    });
    d->cursor = std::make_unique<Cursor>(this);
    d->networkDetection = std::make_unique<NetworkDetection>(this);
    d->clipboard = std::make_unique<Clipboard>(this);
    d->displayControl = std::make_unique<DisplayControl>(this);

    QMetaObject::invokeMethod(this, &RdpConnection::initialize, Qt::QueuedConnection);
}

RdpConnection::~RdpConnection()
{
    // The run thread owns the peer transport and closes it as it exits, so just
    // wake it (stopEvent) and join before we free. Closing the peer here, while
    // the run thread still reads the same transport, races inside FreeRDP and
    // crashes on shutdown.
    if (d->thread.joinable()) {
        d->requestStop();
        d->thread.join();
    } else if (d->peer && d->peer->context && d->state != State::Closed) {
        // The run thread was never started (peer set up but initialize failed):
        // nothing else touches the peer, so close it here before freeing.
        // freerdp_peer_context_new_ex() clears peer->context when it fails, and
        // freerdp_peer_close() asserts on a valid context.
        d->peer->Close(d->peer);
    }

    if (d->peer) {
        // freerdp_peer_free() does not free the context allocated by
        // freerdp_peer_context_new_ex().
        if (d->peer->context) {
            freerdp_peer_context_free(d->peer);
        }
        freerdp_peer_free(d->peer);
    }

    if (d->stopEvent) {
        CloseHandle(d->stopEvent);
    }
    if (d->redirectionEvent) {
        CloseHandle(d->redirectionEvent);
    }
}

RdpConnection::State RdpConnection::state() const
{
    return d->state;
}

QString RdpConnection::username() const
{
    return d->username;
}

QString RdpConnection::clientAddress() const
{
    return d->clientAddress;
}

void RdpConnection::setState(KRdp::RdpConnection::State newState)
{
    if (newState == d->state) {
        return;
    }

    d->state = newState;
    Q_EMIT stateChanged(newState);
}

void RdpConnection::close(RdpConnection::CloseReason reason)
{
    if (d->state == State::Closed) {
        return;
    }

    switch (reason) {
    case CloseReason::VideoInitFailed:
        freerdp_set_error_info(d->peer->context->rdp, ERRINFO_GRAPHICS_SUBSYSTEM_FAILED);
        break;
    case CloseReason::UserLogoff:
        freerdp_set_error_info(d->peer->context->rdp, ERRINFO_LOGOFF_BY_USER);
        break;
    case CloseReason::None:
        break;
    }

    // Hand teardown to the run thread; it owns the peer transport and closes it
    // as it exits. This is called from the main thread (SessionController) and
    // from video-encoding threads (VideoStream), so it must not drive the peer
    // directly - that would race with the run thread reading the same transport.
    d->requestStop();
}

void RdpConnection::sendServerRedirection(const RedirectionInfo &info)
{
    if (d->state == State::Closed) {
        return;
    }

    {
        std::lock_guard lock(d->redirectionMutex);
        d->pendingRedirection = info;
    }
    if (d->redirectionEvent) {
        SetEvent(d->redirectionEvent);
    }
}

bool RdpConnection::sendServerRedirectionOnRunThread(const RedirectionInfo &info)
{
    QFile certificateFile(QString::fromStdString(d->server->tlsCertificate().string()));
    if (!certificateFile.open(QIODevice::ReadOnly)) {
        qCWarning(KRDP) << "Unable to read TLS certificate for redirection:" << d->server->tlsCertificate().string();
        return false;
    }

    rdpRedirection *redirection = createServerRedirection(info, certificateFile.readAll());
    if (!redirection) {
        qCWarning(KRDP) << "Unable to create server redirection";
        return false;
    }

    const auto result = d->peer->SendServerRedirection(d->peer, redirection) == TRUE;
    redirection_free(redirection);
    return result;
}

InputHandler *RdpConnection::inputHandler() const
{
    return d->inputHandler.get();
}

KRdp::VideoStream *RdpConnection::videoStream() const
{
    return d->videoStream.get();
}

Cursor *RdpConnection::cursor() const
{
    return d->cursor.get();
}

Clipboard *RdpConnection::clipboard() const
{
    return d->clipboard.get();
}

DisplayControl *RdpConnection::displayControl() const
{
    return d->displayControl.get();
}

NetworkDetection *RdpConnection::networkDetection() const
{
    return d->networkDetection.get();
}

void RdpConnection::initialize()
{
    setState(State::Starting);

    d->peer = freerdp_peer_new(d->socketHandle);
    if (!d->peer) {
        qCWarning(KRDP) << "Failed to create peer";
        return;
    }

    // Create an instance of our custom PeerContext extended context as context
    // rather than the plain rdpContext.
    d->peer->ContextSize = sizeof(PeerContext);
    d->peer->ContextNew = (psPeerContextNew)newPeerContext;
    d->peer->ContextFree = (psPeerContextFree)freePeerContext;

    auto result = freerdp_peer_context_new_ex(d->peer, d->server->rdpSettings());
    if (!result) {
        qCWarning(KRDP) << "Failed to create peer context";
        return;
    }

    auto context = reinterpret_cast<PeerContext *>(d->peer->context);
    context->connection = this;

    auto settings = d->peer->context->settings;

    const bool usePamAuthentication = d->server->usePAMAuthentication();

    if (!usePamAuthentication) {
        if (!createSamFile(d->samFile, d->server->users())) {
            qFatal("Failed to create SAM database");
            return;
        }

        if (!freerdp_settings_set_string(settings, FreeRDP_NtlmSamFile, d->samFile.fileName().toUtf8().constData())) {
            qFatal("Failed to set SAM database");
            return;
        }
    }

    auto certificate = freerdp_certificate_new_from_file(d->server->tlsCertificate().string().data());
    if (!certificate) {
        qCWarning(KRDP) << "Could not read certificate file" << d->server->tlsCertificate().string();
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, certificate, 1);

    auto key = freerdp_key_new_from_file(d->server->tlsCertificateKey().string().data());
    if (!key) {
        qCWarning(KRDP) << "Could not read certificate file" << d->server->tlsCertificate().string();
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1);

    freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, false);
    freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, usePamAuthentication);
    freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, !usePamAuthentication);
    freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, !usePamAuthentication);

    freerdp_settings_set_uint32(settings, FreeRDP_OsMajorType, OSMAJORTYPE_UNIX);
    // PSEUDO_XSERVER is apparently required for things to work properly.
    freerdp_settings_set_uint32(settings, FreeRDP_OsMinorType, OSMINORTYPE_PSEUDO_XSERVER);

    // TODO: Implement audio support
    freerdp_settings_set_bool(settings, FreeRDP_AudioPlayback, false);

    freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32);

    freerdp_settings_set_bool(settings, FreeRDP_SupportGraphicsPipeline, true);
    freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444v2, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxH264, !VideoStream::h264Disabled());
    freerdp_settings_set_bool(settings, FreeRDP_GfxProgressive, true);
    freerdp_settings_set_bool(settings, FreeRDP_SmartSizing, true);

    freerdp_settings_set_bool(settings, FreeRDP_GfxSmallCache, false);
    freerdp_settings_set_bool(settings, FreeRDP_GfxThinClient, false);
    freerdp_settings_set_bool(settings, FreeRDP_SupportDynamicChannels, true);

    freerdp_settings_set_bool(settings, FreeRDP_HasExtendedMouseEvent, true);
    freerdp_settings_set_bool(settings, FreeRDP_HasHorizontalWheel, true);
    freerdp_settings_set_bool(settings, FreeRDP_UnicodeInput, false);

    // TODO: Implement network performance detection
    freerdp_settings_set_bool(settings, FreeRDP_NetworkAutoDetect, true);

    freerdp_settings_set_bool(settings, FreeRDP_RefreshRect, true);
    freerdp_settings_set_bool(settings, FreeRDP_RemoteConsoleAudio, true);
    freerdp_settings_set_bool(settings, FreeRDP_RemoteFxCodec, false);
    freerdp_settings_set_bool(settings, FreeRDP_NSCodec, false);
    freerdp_settings_set_bool(settings, FreeRDP_FrameMarkerCommandEnabled, true);
    freerdp_settings_set_bool(settings, FreeRDP_SurfaceFrameMarkerEnabled, true);

    freerdp_settings_set_bool(settings, FreeRDP_SupportMonitorLayoutPdu, true);
    freerdp_settings_set_bool(settings, FreeRDP_SupportDisplayControl, true);


    d->peer->Capabilities = peerCapabilities;
    d->peer->Activate = peerActivate;
    d->peer->PostConnect = peerPostConnect;

    d->peer->context->update->SuppressOutput = suppressOutput;

    d->inputHandler->initialize(d->peer->context->input);
    context->inputHandler = d->inputHandler.get();

    context->networkDetection = d->networkDetection.get();
    d->networkDetection->initialize();

    if (!d->peer->Initialize(d->peer)) {
        qCWarning(KRDP) << "Unable to initialize peer";
        return;
    }

    qCDebug(KRDP) << "Session setup completed, start processing...";

    // Manual-reset events the run thread waits on, so teardown and redirection
    // requests can wake it without protocol I/O on the peer. WinPR does not
    // implement auto-reset events, so the run thread resets redirectionEvent
    // itself. Created before the thread starts.
    d->stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    d->redirectionEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!d->stopEvent || !d->redirectionEvent) {
        qCWarning(KRDP) << "Unable to create session events";
        return;
    }

    // Perform actual communication on a separate thread.
    d->thread = std::jthread(std::bind(&RdpConnection::run, this, std::placeholders::_1));
    pthread_setname_np(d->thread.native_handle(), "krdp_session");
}

void RdpConnection::run(std::stop_token stopToken)
{
    auto context = reinterpret_cast<PeerContext *>(d->peer->context);
    auto channelEvent = WTSVirtualChannelManagerGetEventHandle(context->virtualChannelManager);
    BYTE lastDrdynvcState = 0xFF;
    bool lastDrdynvcJoined = false;
    setState(State::Running);

    constexpr size_t kControlEventCount = 3;
    constexpr size_t kMaxPeerHandles = 31;
    constexpr size_t kMaxEvents = kControlEventCount + kMaxPeerHandles;

    while (!stopToken.stop_requested()) {
        // events[0] = virtual channel manager, events[1] = stopEvent (signalled
        // for teardown), events[2] = redirectionEvent (signalled for server
        // redirection), the rest = peer transport handles.
        std::array<HANDLE, kMaxEvents> events{channelEvent, d->stopEvent, d->redirectionEvent};
        auto handleCount = d->peer->GetEventHandles(d->peer, events.data() + kControlEventCount, kMaxPeerHandles);
        if (handleCount <= 0) {
            qCDebug(KRDP) << "Unable to get transport event handles";
            break;
        }
        // Wait for something to happen on the connection.
        WaitForMultipleObjects(kControlEventCount + handleCount, events.data(), FALSE, INFINITE);

        // Bail out before touching the peer transport if we were asked to stop,
        // so teardown stays race-free.
        if (stopToken.stop_requested()) {
            break;
        }

        // Send a server redirection queued by another thread, if any.
        // redirectionEvent is manual-reset: clear it before taking the pending
        // redirection so a request queued after this point re-signals it.
        ResetEvent(d->redirectionEvent);
        std::optional<RedirectionInfo> redirection;
        {
            std::lock_guard lock(d->redirectionMutex);
            redirection.swap(d->pendingRedirection);
        }
        if (redirection) {
            if (!sendServerRedirectionOnRunThread(*redirection)) {
                qCWarning(KRDP) << "Unable to send server redirection";
                break;
            }
        }

        // Read data from the socket and have FreeRDP process it.
        if (d->peer->CheckFileDescriptor(d->peer) != TRUE) {
            qCDebug(KRDP) << "Unable to check file descriptor";
            break;
        }

        const bool cliprdrJoined = WTSVirtualChannelManagerIsChannelJoined(context->virtualChannelManager, CLIPRDR_SVC_CHANNEL_NAME);
        const bool drdynvcJoined = WTSVirtualChannelManagerIsChannelJoined(context->virtualChannelManager, DRDYNVC_SVC_CHANNEL_NAME);
        const BYTE drdynvcState = WTSVirtualChannelManagerGetDrdynvcState(context->virtualChannelManager);

        if (d->peer->connected && d->state == State::Activated && drdynvcJoined && drdynvcState == DRDYNVC_STATE_NONE) {
            if (WTSVirtualChannelManagerOpen(context->virtualChannelManager) != TRUE) {
                qCDebug(KRDP) << "Unable to open Virtual Channel Manager for drdynvc";
                break;
            }
        }

        if (WTSVirtualChannelManagerCheckFileDescriptorEx(context->virtualChannelManager, FALSE) != TRUE) {
            qCDebug(KRDP) << "Unable to check Virtual Channel Manager file descriptor, closing connection";
            break;
        }

        if (d->peer->connected && d->state == State::Activated && cliprdrJoined) {
            if (!d->clipboard->initialize()) {
                break;
            }
        }

        if (d->peer->connected && d->state == State::Activated && drdynvcJoined && drdynvcState == DRDYNVC_STATE_READY) {
            if (!d->displayControl->initialize()) {
                break;
            }
            if (!d->videoStream->initialize()) {
                break;
            }
            d->videoStream->setEnabled(true);
        }

        if (drdynvcJoined != lastDrdynvcJoined || drdynvcState != lastDrdynvcState) {
            lastDrdynvcJoined = drdynvcJoined;
            lastDrdynvcState = drdynvcState;
        }

        if (d->peer->connected && d->state == State::Activated && drdynvcJoined) {
            if (drdynvcState == DRDYNVC_STATE_READY) {
                if (!d->videoStream->openChannel()) {
                    qCWarning(KRDP) << "Unable to open RDPGFX channel";
                } else {
                    setState(State::Streaming);
                }
            }
        }

        d->networkDetection->update();
    }

    qCDebug(KRDP) << "Closing session";

    // Close the peer here, on the thread that owns it. Every other close path
    // just asks this thread to stop, so once a run thread exists this is the
    // only place the transport is driven - keeping teardown single-threaded.
    if (d->peer) {
        d->peer->Close(d->peer);
    }

    onClose();
}

bool RdpConnection::onCapabilities()
{
    auto settings = d->peer->context->settings;
    if (!freerdp_settings_get_bool(settings, FreeRDP_SupportGraphicsPipeline)) {
        qCWarning(KRDP) << "Client does not support graphics pipeline which is required";
        return false;
    }

    auto colorDepth = freerdp_settings_get_uint32(settings, FreeRDP_ColorDepth);
    if (colorDepth != 32) {
        qCDebug(KRDP) << "Correcting invalid color depth from client:" << colorDepth;
        freerdp_settings_set_uint32(settings, FreeRDP_ColorDepth, 32);
    }

    if (freerdp_settings_get_uint32(settings,FreeRDP_PointerCacheSize) <= 0) {
        qCWarning(KRDP) << "Client doesn't support pointer caching, aborting";
        return false;
    }

    return true;
}

static std::optional<quint8> qualitySeedForConnectionType(uint32_t connectionType)
{
    switch (connectionType) {
    case CONNECTION_TYPE_MODEM:
        return 30;
    case CONNECTION_TYPE_BROADBAND_LOW:
        return 50;
    case CONNECTION_TYPE_SATELLITE:
        return 45;
    case CONNECTION_TYPE_WAN:
        return 70;
    case CONNECTION_TYPE_BROADBAND_HIGH:
        return 80;
    case CONNECTION_TYPE_LAN:
        return 95;
    default:
        return std::nullopt;
    }
}

bool RdpConnection::onActivate()
{
    if (!d->videoStream->requestedSize().isValid()) {
        auto settings = d->peer->context->settings;
        const int width = static_cast<int>(freerdp_settings_get_uint32(settings, FreeRDP_DesktopWidth)) & ~1;
        const int height = static_cast<int>(freerdp_settings_get_uint32(settings, FreeRDP_DesktopHeight)) & ~1;
        const QSize clientSize(width, height);
        if (!clientSize.isEmpty()) {
            d->videoStream->setRequestedSize(clientSize);
        }
    }

    setState(State::Activated);

    if (!d->qualitySeeded) {
        d->qualitySeeded = true;
        const uint32_t connectionType = freerdp_settings_get_uint32(d->peer->context->settings, FreeRDP_ConnectionType);
        if (const auto seed = qualitySeedForConnectionType(connectionType)) {
            QMetaObject::invokeMethod(
                d->videoStream.get(),
                [videoStream = d->videoStream.get(), seed = *seed]() {
                    videoStream->seedQuality(seed);
                },
                Qt::QueuedConnection);
        }
    }

    return true;
}

bool RdpConnection::onPostConnect()
{
    qCInfo(KRDP) << "New client connected:" << d->peer->hostname << freerdp_peer_os_major_type_string(d->peer) << freerdp_peer_os_minor_type_string(d->peer);

    rdpSettings *settings = d->peer->context->settings;
    const QString username = QString::fromUtf8(freerdp_settings_get_string(settings, FreeRDP_Username)).section(QLatin1Char('\\'), -1);
    const QString password = QString::fromUtf8(freerdp_settings_get_string(settings, FreeRDP_Password));

    d->username = username;
    d->clientAddress = QString::fromUtf8(d->peer->hostname);

    if (d->server->usePAMAuthentication()) {
        bool systemUserAllowed = false;
        const QString currentUser = KUser().loginName();

        if (currentUser == QStringLiteral("plasmalogin")) {
            systemUserAllowed = true;
        } else if (username == currentUser) {
            systemUserAllowed = true;
        } else if (d->server->allowedSystemUsers().contains(username)) {
            systemUserAllowed = true;
        } else {
            const KUser targetUser(username);
            if (targetUser.isValid()) {
                const auto userGroups = targetUser.groupNames();
                for (const auto &allowedGroup : d->server->allowedSystemGroups()) {
                    if (userGroups.contains(allowedGroup)) {
                        systemUserAllowed = true;
                        break;
                    }
                }
            }
        }

        if (systemUserAllowed) {
            if (!freerdp_settings_set_bool(settings, FreeRDP_AutoLogonEnabled, true)) {
                return false;
            }
            qCDebug(KRDP) << "Attempting authenticating user with PAM:" << username;
            if (pamAuthenticate(username, password) >= 0) {
                qCDebug(KRDP) << "PAM authentication succeeded for user" << username;
                return true;
            } else {
                qCWarning(KRDP) << "PAM authentication failed for user" << username;
            }
        }

        const auto users = d->server->users();
        for (const auto &user : users) {
            if (user.password.isEmpty()) {
                continue;
            }
            if (user.name == username && user.password == password) {
                qCDebug(KRDP) << "User" << username << "authenticated successfully via guest credentials";
                return true;
            }
        }
        return false;
    } else {
        // In the NLA case the user has been authorised against the SAM database
        return true;
    }
}

bool RdpConnection::onClose()
{
    d->displayControl->close();
    d->clipboard->close();
    d->videoStream->close();
    setState(State::Closed);
    return true;
}

bool RdpConnection::onSuppressOutput(uint8_t allow)
{
    if (allow) {
        d->videoStream->setEnabled(true);
    } else {
        d->videoStream->setEnabled(false);
    }

    return true;
}

freerdp_peer *RdpConnection::rdpPeer() const
{
    return d->peer;
}

rdpContext *RdpConnection::rdpPeerContext() const
{
    return d->peer->context;
}
}

#include "moc_RdpConnection.cpp"
