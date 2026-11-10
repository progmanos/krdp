// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "NotificationUtil.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QStringList>
#include <QVariantMap>

using namespace Qt::StringLiterals;

namespace
{
constexpr auto kNotificationsService = "org.freedesktop.Notifications"_L1;
constexpr auto kNotificationsPath = "/org/freedesktop/Notifications"_L1;
constexpr auto kNotificationsInterface = "org.freedesktop.Notifications"_L1;
constexpr auto kNotifyMethod = "Notify"_L1;
constexpr auto kNotifyAppName = "KRdp"_L1;
constexpr auto kDefaultNotificationIcon = "preferences-system-network-remote"_L1;
constexpr auto kClientLabelFormat = "%1 (%2)"_L1;

// Per the Desktop Notifications Specification, replaces_id = 0 allocates a new
// notification, and expire_timeout = -1 delegates display duration to server config.
constexpr uint kReplaceNoNotificationId = 0;
constexpr int kNotificationDefaultTimeout = -1;
}

namespace KRdpServer
{

namespace NotificationUtil
{
void sendNotification(const QString &title, const QString &body)
{
    sendNotification(title, body, kDefaultNotificationIcon.toString());
}

void sendNotification(const QString &title, const QString &body, const QString &icon)
{
    auto notifyMsg = QDBusMessage::createMethodCall(kNotificationsService.toString(),
                                                    kNotificationsPath.toString(),
                                                    kNotificationsInterface.toString(),
                                                    kNotifyMethod.toString());
    notifyMsg << kNotifyAppName.toString() << kReplaceNoNotificationId << icon << title << body << QStringList{} << QVariantMap{}
              << kNotificationDefaultTimeout;
    QDBusConnection::sessionBus().call(notifyMsg, QDBus::NoBlock);
}
}

namespace ClientUtil
{
QString formatClientLabel(const QString &user, const QString &addr)
{
    if (!user.isEmpty() && !addr.isEmpty()) {
        return kClientLabelFormat.toString().arg(user, addr);
    }
    return !user.isEmpty() ? user : addr;
}
}

} // namespace KRdpServer
