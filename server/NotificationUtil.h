// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <QString>

namespace KRdpServer
{

namespace NotificationUtil
{
/**
 * Dispatches a desktop notification over the user session D-Bus
 * (org.freedesktop.Notifications).
 */
void sendNotification(const QString &title, const QString &body);
void sendNotification(const QString &title, const QString &body, const QString &icon);
}

namespace ClientUtil
{
/**
 * Formats user and IP address into a user-friendly label (e.g. "user (1.2.3.4)").
 * Omits empty parentheses if address or username is missing.
 */
QString formatClientLabel(const QString &user, const QString &addr);
}

} // namespace KRdpServer
