// SPDX-FileCopyrightText: 2025 David Edmundson <davidedmundson@kde.org>
//
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "DisplayControl.h"
#include "PeerContext_p.h"
#include "RdpConnection.h"

#include <algorithm>

#include <QDebug>
#include <QSize>

#include <freerdp/peer.h>

#include "krdp_logging.h"

using namespace KRdp;

namespace
{
constexpr int kMinDisplayDimension = 200;
constexpr int kMaxDisplayDimension = 8192;
constexpr uint32_t kMaxMonitors = 16;
constexpr uint32_t kMaxMonitorAreaFactor = 8192;
}

static UINT display_control_receive_monitor_layout(DispServerContext *context, const DISPLAY_CONTROL_MONITOR_LAYOUT_PDU *pdu)
{
    if (!pdu || pdu->NumMonitors < 1 || !pdu->Monitors) {
        return CHANNEL_RC_BAD_CHANNEL;
    }

    const DISPLAY_CONTROL_MONITOR_LAYOUT *selectedMonitor = &pdu->Monitors[0];
    for (UINT32 i = 0; i < pdu->NumMonitors; ++i) {
        if (pdu->Monitors[i].Flags & DISPLAY_CONTROL_MONITOR_PRIMARY) {
            selectedMonitor = &pdu->Monitors[i];
            break;
        }
    }

    const int width = std::clamp<int>(selectedMonitor->Width, kMinDisplayDimension, kMaxDisplayDimension) & ~1;
    const int height = std::clamp<int>(selectedMonitor->Height, kMinDisplayDimension, kMaxDisplayDimension) & ~1;
    const QSize monitorSize(width, height);

    auto c = static_cast<DisplayControl *>(context->custom);
    c->setRequestedMonitorSize(monitorSize);

    return CHANNEL_RC_OK;
}

void DisplayControl::setRequestedMonitorSize(const QSize &size)
{
    if (m_lastSize == size) {
        return;
    }
    m_lastSize = size;
    Q_EMIT requestedScreenSizeChanged(size);
}

DisplayControl::DisplayControl(RdpConnection *session)
    : m_session(session)
{
}

bool DisplayControl::initialize()
{
    if (m_dispManager) {
        return true;
    }

    auto peerContext = reinterpret_cast<PeerContext *>(m_session->rdpPeer()->context);

    m_dispManager = disp_server_context_new(peerContext->virtualChannelManager);
    if (!m_dispManager) {
        qCWarning(KRDP) << "Failed creating DisplayControl context";
        return false;
    }

    m_dispManager->rdpcontext = m_session->rdpPeer()->context;
    m_dispManager->custom = this;

    m_dispManager->DispMonitorLayout = display_control_receive_monitor_layout;

    m_dispManager->MaxNumMonitors = kMaxMonitors;
    m_dispManager->MaxMonitorAreaFactorA = kMaxMonitorAreaFactor;
    m_dispManager->MaxMonitorAreaFactorB = kMaxMonitorAreaFactor;

    if (m_dispManager->Open(m_dispManager) != CHANNEL_RC_OK) {
        qCWarning(KRDP) << "Could not open DisplayControl context";
        return false;
    }
    if (m_dispManager->DisplayControlCaps(m_dispManager) != CHANNEL_RC_OK) {
        qCWarning(KRDP) << "Could not advertise DisplayControl capabilities";
        return false;
    }

    return true;
}

void DisplayControl::close()
{
    m_lastSize = QSize();
    if (m_dispManager) {
        disp_server_context_free(m_dispManager);
        m_dispManager = nullptr;
    }
}
