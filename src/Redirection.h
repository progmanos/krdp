// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <QString>

#include "krdp_export.h"

struct rdp_redirection;

namespace KRdp
{

/**
 * The information required to redirect an RDP client to another KRdp session.
 *
 * This is used by the RDP Server Redirection mechanism: the source session
 * sends a ServerRedirection PDU containing a routing token and one-time
 * credentials. The client disconnects and reconnects to the same address,
 * sending the routing token in its X.224 Connection Request. The dispatcher
 * matches that token back to the session server that wants to take over the
 * client.
 */
struct KRDP_EXPORT RedirectionInfo {
    /**
     * The unique remote id that also acts as the routing token. The client
     * presents this token when it reconnects.
     */
    QString routingToken;
    /**
     * One-time username the redirected client authenticates with against the
     * destination session.
     */
    QString username;
    /**
     * One-time password the redirected client authenticates with against the
     * destination session.
     */
    QString password;
};

/**
 * Build a FreeRDP @c rdpRedirection object from @p info.
 *
 * The result is serialised into the ServerRedirection PDU by FreeRDP and must
 * be released with @c redirection_free() once the PDU has been sent.
 *
 * @param info The redirection information.
 * @param certificatePem The DER-encoded TLS certificate, as PEM, of the
 *        destination session. It is forwarded to the client so it can verify
 *        the destination server's identity.
 * @return A newly allocated @c rdpRedirection, or @c nullptr on failure.
 */
KRDP_EXPORT rdp_redirection *createServerRedirection(const RedirectionInfo &info, const QByteArray &certificatePem);

}