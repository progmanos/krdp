// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "DispatcherConnection.h"

#include <array>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <optional>
#include <sys/socket.h>

#include <QFile>

#include <freerdp/freerdp.h>
#include <freerdp/peer.h>

#include "Dispatcher.h"
#include "Redirection.h"

#include "krdp_logging.h"

namespace
{

/**
 * Extension of the FreeRDP Peer Context used to store extra data.
 */
struct DispatcherPeerContext {
    // The base rdpContext structure.
    // Important: This should remain as a plain value as that is how the
    // extension mechanism works.
    rdpContext _p;

    KRdp::DispatcherConnection *connection = nullptr;
};

BOOL newPeerContext(freerdp_peer * /*peer*/, rdpContext *peer_context)
{
    auto context = reinterpret_cast<DispatcherPeerContext *>(peer_context);
    context->connection = nullptr;
    return TRUE;
}

void freePeerContext(freerdp_peer * /*peer*/, rdpContext * /*peer_context*/)
{
}

}

namespace KRdp
{

BOOL dispatcherPeerPostConnect(freerdp_peer *peer)
{
    auto context = reinterpret_cast<DispatcherPeerContext *>(peer->context);
    context->connection->onPeerConnected();
    return TRUE;
}

BOOL dispatcherPeerActivate(freerdp_peer *peer)
{
    auto context = reinterpret_cast<DispatcherPeerContext *>(peer->context);
    context->connection->onPeerActivated();
    return TRUE;
}

class KRDP_NO_EXPORT DispatcherConnection::Private
{
public:
    Dispatcher *dispatcher = nullptr;

    qintptr socketHandle = -1;

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

    // Whether the client has completed the RDP handshake with the dispatcher.
    // Only touched from the run thread.
    bool connected = false;
};

DispatcherConnection::DispatcherConnection(Dispatcher *dispatcher, qintptr socketHandle)
    : QObject(dispatcher)
    , d(std::make_unique<Private>())
{
    d->dispatcher = dispatcher;
    d->socketHandle = socketHandle;

    QMetaObject::invokeMethod(this, &DispatcherConnection::initialize, Qt::QueuedConnection);
}

DispatcherConnection::~DispatcherConnection()
{
    // The run thread owns the peer and closes it as it exits.
    if (d->thread.joinable()) {
        requestStop();
        d->thread.join();
    } else if (d->peer && d->peer->context && !d->connected) {
        // The run thread was never started: nothing else touches the peer, so
        // close it here before freeing. freerdp_peer_context_new_ex() clears
        // peer->context when it fails, and freerdp_peer_close() asserts on a
        // valid context, so only close a peer whose context was created.
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

void DispatcherConnection::requestStop()
{
    d->thread.request_stop();
    if (d->stopEvent) {
        SetEvent(d->stopEvent);
    }
}

void DispatcherConnection::sendServerRedirection(const RedirectionInfo &info)
{
    {
        std::lock_guard lock(d->redirectionMutex);
        d->pendingRedirection = info;
    }
    if (d->redirectionEvent) {
        SetEvent(d->redirectionEvent);
    }
}

void DispatcherConnection::initialize()
{
    d->peer = freerdp_peer_new(d->socketHandle);
    if (!d->peer) {
        qCWarning(KRDP) << "Failed to create peer";
        Q_EMIT closed();
        return;
    }

    d->peer->ContextSize = sizeof(DispatcherPeerContext);
    d->peer->ContextNew = (psPeerContextNew)newPeerContext;
    d->peer->ContextFree = (psPeerContextFree)freePeerContext;

    auto result = freerdp_peer_context_new_ex(d->peer, d->dispatcher->rdpSettings());
    if (!result) {
        // A common cause is a missing HOME environment variable: FreeRDP
        // refuses to create settings without one.
        qCWarning(KRDP) << "Failed to create peer context";
        Q_EMIT closed();
        return;
    }

    auto context = reinterpret_cast<DispatcherPeerContext *>(d->peer->context);
    context->connection = this;

    auto settings = d->peer->context->settings;

    auto certificate = freerdp_certificate_new_from_file(d->dispatcher->systemCertificate().string().data());
    if (!certificate) {
        qCWarning(KRDP) << "Could not read certificate file" << d->dispatcher->systemCertificate().string();
        Q_EMIT closed();
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerCertificate, certificate, 1);

    auto key = freerdp_key_new_from_file(d->dispatcher->systemCertificateKey().string().data());
    if (!key) {
        qCWarning(KRDP) << "Could not read certificate key file" << d->dispatcher->systemCertificateKey().string();
        Q_EMIT closed();
        return;
    }
    freerdp_settings_set_pointer_len(settings, FreeRDP_RdpServerRsaKey, key, 1);

    // The client is only ever redirected to its actual session, so a plain
    // TLS handshake is all that is needed here. Credential validation happens
    // at the destination session.
    freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, false);
    freerdp_settings_set_bool(settings, FreeRDP_TlsSecurity, true);
    freerdp_settings_set_bool(settings, FreeRDP_NlaSecurity, false);
    freerdp_settings_set_bool(settings, FreeRDP_ExtSecurity, false);

    freerdp_settings_set_uint32(settings, FreeRDP_OsMajorType, OSMAJORTYPE_UNIX);
    // PSEUDO_XSERVER is apparently required for things to work properly.
    freerdp_settings_set_uint32(settings, FreeRDP_OsMinorType, OSMINORTYPE_PSEUDO_XSERVER);

    d->peer->PostConnect = dispatcherPeerPostConnect;
    d->peer->Activate = dispatcherPeerActivate;

    if (!d->peer->Initialize(d->peer)) {
        qCWarning(KRDP) << "Unable to initialize peer";
        Q_EMIT closed();
        return;
    }

    qCDebug(KRDP) << "Dispatcher connection initialized, start processing...";

    // WinPR does not implement auto-reset events, so both are manual-reset and
    // the run thread resets redirectionEvent itself.
    d->stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    d->redirectionEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!d->stopEvent || !d->redirectionEvent) {
        qCWarning(KRDP) << "Unable to create dispatcher connection events";
        Q_EMIT closed();
        return;
    }

    d->thread = std::jthread(std::bind(&DispatcherConnection::run, this, std::placeholders::_1));
    pthread_setname_np(d->thread.native_handle(), "krdp_dispatcher");
}

void DispatcherConnection::run(std::stop_token stopToken)
{
    while (!stopToken.stop_requested()) {
        // events[0] = stopEvent (signalled for teardown), events[1] =
        // redirectionEvent (signalled for server redirection), the rest = peer
        // transport handles.
        std::array<HANDLE, 34> events{d->stopEvent, d->redirectionEvent};
        auto handleCount = d->peer->GetEventHandles(d->peer, events.data() + 2, 32);
        if (handleCount <= 0) {
            qCDebug(KRDP) << "Unable to get transport event handles";
            break;
        }
        // Wait for something to happen on the connection.
        WaitForMultipleObjects(2 + handleCount, events.data(), FALSE, INFINITE);

        // Bail out before touching the peer transport if we were asked to stop.
        if (stopToken.stop_requested()) {
            break;
        }

        // redirectionEvent is manual-reset: clear it before looking at the
        // pending redirection so a request queued after this point re-signals
        // it and is not lost.
        ResetEvent(d->redirectionEvent);

        // Read data from the socket and have FreeRDP process it. This drives
        // the handshake and invokes PostConnect on this thread.
        if (d->peer->CheckFileDescriptor(d->peer) != TRUE) {
            qCDebug(KRDP) << "Unable to check file descriptor";
            break;
        }

        // Send a server redirection queued by another thread, once the
        // handshake has completed. Until then it stays queued and is picked up
        // on a later iteration.
        if (d->connected) {
            std::optional<RedirectionInfo> redirection;
            {
                std::lock_guard lock(d->redirectionMutex);
                redirection.swap(d->pendingRedirection);
            }
            if (redirection && !sendServerRedirectionOnRunThread(*redirection)) {
                qCWarning(KRDP) << "Unable to send server redirection";
                break;
            }
        }
    }

    qCDebug(KRDP) << "Closing dispatcher connection";

    // Close the peer here, on the thread that owns it.
    if (d->peer) {
        d->peer->Close(d->peer);
    }

    Q_EMIT closed();
}

void DispatcherConnection::onPeerConnected()
{
    qCDebug(KRDP) << "Client connected to the dispatcher:" << d->peer->hostname;
}

void DispatcherConnection::onPeerActivated()
{
    qCDebug(KRDP) << "Client activated on the dispatcher:" << d->peer->hostname;
    if (!d->connected) {
        d->connected = true;
        Q_EMIT connected();
    }
}

bool DispatcherConnection::sendServerRedirectionOnRunThread(const RedirectionInfo &info)
{
    QFile certificateFile(QString::fromStdString(d->dispatcher->systemCertificate().string()));
    if (!certificateFile.open(QIODevice::ReadOnly)) {
        qCWarning(KRDP) << "Unable to read system certificate for redirection:" << d->dispatcher->systemCertificate().string();
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

} // namespace KRdp

#include "moc_DispatcherConnection.cpp"