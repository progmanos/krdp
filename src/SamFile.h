// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#pragma once

#include <QList>
#include <QTemporaryFile>

#include "krdp_export.h"

namespace KRdp
{

struct User;

/**
 * Create the "sam" file used by FreeRDP for reading username and password
 * information.
 *
 * It hashes the password of every entry in @p users in the appropriate NTLM
 * format and writes that along with the username to the provided temporary
 * file. The file must be kept alive for as long as FreeRDP needs it.
 *
 * @param file A temporary file that will be opened and filled by this
 *        function.
 * @param users The users that are allowed to authenticate. At least one entry
 *        is required.
 * @return @c true if the file was written successfully.
 */
KRDP_EXPORT bool createSamFile(QTemporaryFile &file, const QList<User> &users);

}