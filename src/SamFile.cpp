// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "SamFile.h"

#include <array>
#include <filesystem>

#include <QStandardPaths>

#include <winpr/ntlm.h>

#include "Server.h"

namespace fs = std::filesystem;

namespace KRdp
{

bool createSamFile(QTemporaryFile &file, const QList<User> &users)
{
    auto runtimePath = fs::path(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation).toStdString());

    auto path = runtimePath / "krdp";
    fs::create_directories(path);

    file.setFileTemplate(QString::fromStdString(path / "rdp-sam-XXXXXX"));
    if (!file.open()) {
        return false;
    }

    QString data;

    for (const auto &user : users) {
        auto username = user.name;
        auto password = user.password.toUtf8();

        std::array<uint8_t, 16> hash;
        NTOWFv1A((LPSTR)password.data(), password.size(), hash.data());

        auto entry = QStringLiteral("%1:::").arg(username);
        for (int i = 0; i < 16; ++i) {
            entry.append(QStringLiteral("%1").arg(hash[i], 2, 16, QLatin1Char('0')));
        }
        entry.append(QStringLiteral(":::\n"));
        data.append(entry);
    }

    file.write(data.toUtf8());
    file.close();

    return true;
}

}