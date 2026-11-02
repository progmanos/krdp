// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <memory>

#include <QObject>
#include <QPointer>

#include "RdpConnection.h"
#include <Server.h>

class QTemporaryDir;

namespace KRdp
{
class HandoverClient;
}

/**
 * Drives the session side of a remote login handover with the KRdp
 * Dispatcher.
 *
 * A session daemon started for a remote login runs inside the session that
 * should serve the RDP client (the greeter or the user session). This class
 * registers the session with the dispatcher, redirects the client to another
 * session when asked and adopts the client socket when the dispatcher hands
 * it over.
 */
class HandoverManager : public QObject
{
    Q_OBJECT

public:
    HandoverManager(const QString &remoteId, KRdp::Server *server, bool terminateOnDisconnect = true, QObject *parent = nullptr);
    ~HandoverManager() override;

    /**
     * Start the handover: generate one-time credentials, ask the dispatcher
     * to redirect the client to this session and wire up the client socket
     * handover.
     */
    void start();

private:
    void requestHandover();
    void applyCertificate(const QString &certificate, const QString &key);
    void onTakeClientReady(const QString &remoteId);
    void onRedirectClient(const QString &remoteId, const QString &username, const QString &password);

    QString m_remoteId;
    KRdp::Server *m_server;
    bool m_terminateOnDisconnect = true;
    std::unique_ptr<KRdp::HandoverClient> m_handover;
    std::unique_ptr<QTemporaryDir> m_certificateDir;
    QString m_certificatePath;
    QString m_certificateKeyPath;
    KRdp::User m_oneTimeUser;
    QPointer<KRdp::RdpConnection> m_currentConnection;
    int m_handoverAttempts = 0;
};
