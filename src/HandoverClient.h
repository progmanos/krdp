// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <functional>
#include <memory>

#include <QObject>

#include "krdp_export.h"

class OrgKdeKrdpDispatcherInterface;

namespace KRdp
{

/**
 * Client for the org.kde.krdp.Dispatcher D-Bus interface.
 *
 * Used by session daemons (the greeter and the user session) to hand over a
 * remote RDP client with the system dispatcher. See the Dispatcher class for
 * a description of the handover protocol.
 */
class KRDP_EXPORT HandoverClient : public QObject
{
    Q_OBJECT

public:
    explicit HandoverClient(QObject *parent = nullptr);
    ~HandoverClient() override;

    /**
     * The result of a StartHandover call.
     */
    struct HandoverResult {
        /**
         * PEM certificate the session should use for its RDP listener.
         */
        QString certificate;
        /**
         * PEM private key matching certificate.
         */
        QString certificateKey;
    };

    /**
     * Whether the dispatcher is registered on the D-Bus.
     */
    bool isAvailable() const;

    /**
     * Request the remote client with id \p remoteId to be redirected to this
     * session.
     *
     * \param remoteId The remote id this session was started for.
     * \param username One-time username for the redirected client.
     * \param password One-time password for the redirected client.
     * \param callback Invoked with @c true and the results on success.
     */
    void startHandover(const QString &remoteId, const QString &username, const QString &password, std::function<void(bool, const HandoverResult &)> callback);

    /**
     * Retrieve the socket of the reconnected remote client.
     *
     * Should only be called after a takeClientReady() signal has been
     * received.
     *
     * \param remoteId The remote id this session was started for.
     * \param callback Invoked with @c true and the socket file descriptor on
     *        success. The descriptor is a duplicate that the caller owns.
     */
    void takeClient(const QString &remoteId, std::function<void(bool, int)> callback);

    /**
     * Emitted when a reconnected client is ready to be retrieved via
     * takeClient().
     */
    Q_SIGNAL void takeClientReady(const QString &remoteId);
    /**
     * Emitted when the dispatcher asks this session to redirect its RDP client
     * to another session.
     */
    Q_SIGNAL void redirectClient(const QString &remoteId, const QString &username, const QString &password);
    /**
     * Emitted when a new client has connected to the dispatcher.
     */
    Q_SIGNAL void clientConnected(const QString &remoteId);
    /**
     * Emitted when a client has disconnected from the dispatcher.
     */
    Q_SIGNAL void clientDisconnected(const QString &remoteId);

private:
    class Private;
    const std::unique_ptr<Private> d;
};

}