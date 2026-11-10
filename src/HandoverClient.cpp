// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "HandoverClient.h"

#include <fcntl.h>
#include <unistd.h>

#include <QDBusPendingCallWatcher>
#include <QDBusUnixFileDescriptor>

#include "org.kde.krdp.Dispatcher.h"

using namespace Qt::StringLiterals;

namespace
{
constexpr auto kDispatcherService = "org.kde.krdp.Dispatcher"_L1;
constexpr auto kDispatcherPath = "/org/kde/krdp/Dispatcher"_L1;
constexpr auto kStartHandoverMethod = "StartHandover"_L1;
constexpr auto kTakeClientMethod = "TakeClient"_L1;
}

namespace KRdp
{

class KRDP_NO_EXPORT HandoverClient::Private
{
public:
    OrgKdeKrdpDispatcherInterface *interface = nullptr;
};

HandoverClient::HandoverClient(QObject *parent)
    : QObject(parent)
    , d(std::make_unique<Private>())
{
    d->interface = new OrgKdeKrdpDispatcherInterface(kDispatcherService.toString(), kDispatcherPath.toString(), QDBusConnection::systemBus(), this);

    connect(d->interface, &OrgKdeKrdpDispatcherInterface::HandoverRequested, this, &HandoverClient::handoverRequested);
    connect(d->interface, &OrgKdeKrdpDispatcherInterface::TakeClientReady, this, &HandoverClient::takeClientReady);
    connect(d->interface, &OrgKdeKrdpDispatcherInterface::RedirectClient, this, &HandoverClient::redirectClient);
    connect(d->interface, &OrgKdeKrdpDispatcherInterface::ClientConnected, this, &HandoverClient::clientConnected);
    connect(d->interface, &OrgKdeKrdpDispatcherInterface::ClientDisconnected, this, &HandoverClient::clientDisconnected);
}

HandoverClient::~HandoverClient() = default;

bool HandoverClient::isAvailable() const
{
    return d->interface->isValid();
}

void HandoverClient::startHandover(const QString &remoteId,
                                   const QString &username,
                                   const QString &password,
                                   std::function<void(bool, const HandoverResult &)> callback)
{
    auto *watcher = new QDBusPendingCallWatcher(d->interface->asyncCall(kStartHandoverMethod.toString(), remoteId, username, password), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, callback, watcher]() {
        const QDBusMessage reply = watcher->reply();
        watcher->deleteLater();

        HandoverResult result;
        bool success = reply.type() == QDBusMessage::ReplyMessage && reply.arguments().size() == 2;
        if (success) {
            result.certificate = reply.arguments().at(0).toString();
            result.certificateKey = reply.arguments().at(1).toString();
        } else {
            qWarning() << "StartHandover failed:" << reply.errorMessage();
        }

        callback(success, result);
    });
}

void HandoverClient::takeClient(const QString &remoteId, std::function<void(bool, int)> callback)
{
    auto *watcher = new QDBusPendingCallWatcher(d->interface->asyncCall(kTakeClientMethod.toString(), remoteId), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, callback, watcher]() {
        const QDBusMessage reply = watcher->reply();
        watcher->deleteLater();

        int fd = -1;
        bool success = reply.type() == QDBusMessage::ReplyMessage && !reply.arguments().isEmpty();
        if (success) {
            const QDBusUnixFileDescriptor descriptor = qvariant_cast<QDBusUnixFileDescriptor>(reply.arguments().constFirst());
            success = descriptor.isValid();
            if (success) {
                // The descriptor returned by fileDescriptor() already is a
                // duplicate; make a private copy with FD_CLOEXEC set.
                fd = ::dup(descriptor.fileDescriptor());
                if (fd >= 0) {
                    fcntl(fd, F_SETFD, FD_CLOEXEC);
                } else {
                    success = false;
                }
            }
        } else {
            qWarning() << "TakeClient failed:" << reply.errorMessage();
        }

        callback(success, fd);
    });
}

} // namespace KRdp

#include "moc_HandoverClient.cpp"