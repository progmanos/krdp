// SPDX-FileCopyrightText: 2026 Nicolas Fella <nicolas.fella@gmx.de>
// SPDX-License-Identifier: LGPL-2.1-only OR LGPL-3.0-only OR LicenseRef-KDE-Accepted-LGPL

#include "Redirection.h"

#include <memory>

#include <QUuid>

#include <freerdp/crypto/certificate.h>
#include <freerdp/redirection.h>

using namespace Qt::StringLiterals;

namespace
{

// [MS-RDPBCGR] 2.2.14.1: element type and encoding of a TargetCertificate
// payload. These are not part of the public FreeRDP headers.
constexpr uint32_t kCertificateElementType = 32; // CERT_cert_file_element
constexpr uint32_t kEncodingTypeAsn1Der = ENCODING_TYPE_ASN1_DER;

using RedirectionPtr = std::unique_ptr<rdp_redirection, decltype(&redirection_free)>;

/**
 * Encode a string as a UTF-16 (little-endian) buffer, including the trailing
 * null terminator. The RDP redirection PDU uses this encoding for the password
 * and redirection GUID fields.
 */
QByteArray toUtf16(const QString &string)
{
    QByteArray result;
    result.reserve((string.size() + 1) * 2);
    for (const QChar c : string) {
        const char16_t value = c.unicode();
        result.append(char(value & 0xFF));
        result.append(char((value >> 8) & 0xFF));
    }
    result.append('\0');
    result.append('\0');
    return result;
}

/**
 * Wrap a DER-encoded certificate in the container format that the
 * ServerRedirection PDU expects for LB_TARGET_CERTIFICATE.
 */
QByteArray certificateContainer(const QByteArray &der)
{
    QByteArray result;
    result.reserve(3 * 4 + der.size());

    auto writeUint32 = [&result](uint32_t value) {
        result.append(char(value & 0xFF));
        result.append(char((value >> 8) & 0xFF));
        result.append(char((value >> 16) & 0xFF));
        result.append(char((value >> 24) & 0xFF));
    };

    writeUint32(kCertificateElementType);
    writeUint32(kEncodingTypeAsn1Der);
    writeUint32(uint32_t(der.size()));
    result.append(der);

    return result;
}

bool setByteOption(rdpRedirection *redirection, uint32_t flag, const QByteArray &data)
{
    return redirection_set_byte_option(redirection, flag, reinterpret_cast<const BYTE *>(data.constData()), data.size());
}

bool addTargetCertificate(rdpRedirection *redirection, const QByteArray &certificatePem)
{
    if (certificatePem.isEmpty()) {
        return false;
    }

    std::unique_ptr<rdpCertificate, decltype(&freerdp_certificate_free)> certificate(freerdp_certificate_new_from_pem(certificatePem.constData()),
                                                                                     &freerdp_certificate_free);
    if (!certificate) {
        return false;
    }

    size_t derLength = 0;
    BYTE *der = freerdp_certificate_get_der(certificate.get(), &derLength);
    if (!der) {
        return false;
    }

    const QByteArray container = certificateContainer(QByteArray(reinterpret_cast<const char *>(der), int(derLength)));
    free(der);

    return setByteOption(redirection, LB_TARGET_CERTIFICATE, container);
}

}

namespace KRdp
{

rdp_redirection *createServerRedirection(const RedirectionInfo &info, const QByteArray &certificatePem)
{
    RedirectionPtr redirection(redirection_new(), redirection_free);
    if (!redirection) {
        return nullptr;
    }

    uint32_t flags = 0;

    // The routing token. FreeRDP prefixes the value written here with
    // "Cookie: msts=" when serialising the PDU, so the raw remote id is used
    // as the value.
    const auto routingToken = info.routingToken.toUtf8();
    if (!setByteOption(redirection.get(), LB_LOAD_BALANCE_INFO, routingToken)) {
        return nullptr;
    }
    flags |= LB_LOAD_BALANCE_INFO;

    // One-time credentials for the destination session.
    const auto username = info.username.toUtf8();
    if (!redirection_set_string_option(redirection.get(), LB_USERNAME, username.constData())) {
        return nullptr;
    }
    flags |= LB_USERNAME;

    const auto password = toUtf16(info.password);
    if (!setByteOption(redirection.get(), LB_PASSWORD, password)) {
        return nullptr;
    }
    flags |= LB_PASSWORD;

    // A unique identifier for this redirection, required by [MS-RDPBCGR] and
    // used by clients such as mstsc to detect that a redirection actually
    // happened.
    const auto guidUtf16 = toUtf16(QString::fromLatin1(QUuid::createUuid().toRfc4122().toBase64()));
    if (!setByteOption(redirection.get(), LB_REDIRECTION_GUID, guidUtf16)) {
        return nullptr;
    }
    flags |= LB_REDIRECTION_GUID;

    // The destination certificate, so that the client can verify the identity
    // of the server it is being redirected to.
    if (addTargetCertificate(redirection.get(), certificatePem)) {
        flags |= LB_TARGET_CERTIFICATE;
    }

    if (!redirection_set_flags(redirection.get(), flags)) {
        return nullptr;
    }

    uint32_t invalidFlags = 0;
    if (!redirection_settings_are_valid(redirection.get(), &invalidFlags)) {
        return nullptr;
    }

    return redirection.release();
}

}