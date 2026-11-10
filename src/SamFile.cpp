// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "SamFile.h"

#include <array>
#include <filesystem>

#include <QStandardPaths>

#include <winpr/ntlm.h>

#include "Server.h"

namespace fs = std::filesystem;

namespace
{
using namespace Qt::StringLiterals;
constexpr auto kRuntimeSubdir = "krdp"_L1;
constexpr auto kSamTemplatePrefix = "rdp-sam-XXXXXX"_L1;
constexpr auto kSamEntryFormat = "%1:::%2:::\n"_L1;
}

namespace KRdp
{

bool createSamFile(QTemporaryFile &file, const QList<User> &users)
{
    auto runtimePath = fs::path(QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation).toStdString());

    auto path = runtimePath / kRuntimeSubdir.toString().toStdString();
    std::error_code ec;
    fs::create_directories(path, ec);
    fs::permissions(path, fs::perms::owner_all, fs::perm_options::replace, ec);

    file.setFileTemplate(QString::fromStdString((path / kSamTemplatePrefix.toString().toStdString()).string()));
    if (!file.open()) {
        return false;
    }
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);

    QString data;

    for (const auto &user : users) {
        auto password = user.password.toUtf8();

        std::array<uint8_t, 16> hash;
        NTOWFv1A(reinterpret_cast<LPSTR>(password.data()), password.size(), hash.data());

        const auto hashHex = QString::fromLatin1(QByteArray::fromRawData(reinterpret_cast<const char *>(hash.data()), hash.size()).toHex());
        hash.fill(0);

        data.append(kSamEntryFormat.toString().arg(user.name, hashHex));
    }

    file.write(data.toUtf8());
    file.close();

    return true;
}

}