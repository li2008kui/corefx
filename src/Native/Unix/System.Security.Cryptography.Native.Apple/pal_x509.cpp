// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509.h"

extern "C" int32_t AppleCryptoNative_X509ImportCertificate(
    uint8_t* pbData, int32_t cbData, SecCertificateRef* pCertOut, SecKeyRef* pPrivateKeyOut, int32_t* pOSStatus)
{
    if (pCertOut != nullptr)
        *pCertOut = nullptr;
    if (pPrivateKeyOut != nullptr)
        *pPrivateKeyOut = nullptr;
    if (pOSStatus != nullptr)
        *pOSStatus = noErr;

    if (pbData == nullptr || cbData < 0 || pCertOut == nullptr || pPrivateKeyOut == nullptr)
    {
        return kErrorBadInput;
    }

    CFDataRef cfData = CFDataCreateWithBytesNoCopy(nullptr, pbData, cbData, kCFAllocatorNull);

    if (cfData == nullptr)
    {
        return kErrorUnknownState;
    }

    SecExternalFormat dataFormat = kSecFormatUnknown;

    SecExternalItemType itemType = kSecItemTypeCertificate;
    SecExternalItemType actualType = itemType;

    int32_t ret = 0;
    CFIndex itemCount;
    CFArrayRef outItems = nullptr;
    CFTypeRef outItem = nullptr;

    *pOSStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, &outItems);

    if (*pOSStatus != noErr)
    {
        ret = 0;
        goto cleanup;
    }

    if (outItems == nullptr)
    {
        ret = -1;
        goto cleanup;
    }

    itemCount = CFArrayGetCount(outItems);

    if (itemCount == 0)
    {
        ret = -2;
        goto cleanup;
    }

    if (actualType == kSecItemTypeCertificate)
    {
        if (itemCount > 1)
        {
            ret = -4;
            goto cleanup;
        }

        outItem = CFArrayGetValueAtIndex(outItems, 0);

        if (outItem == nullptr)
        {
            ret = -5;
            goto cleanup;
        }

        if (CFGetTypeID(outItem) != SecCertificateGetTypeID())
        {
            ret = -6;
            goto cleanup;
        }

        CFRetain(outItem);
        *pCertOut = reinterpret_cast<SecCertificateRef>(const_cast<void*>(outItem));
        ret = 1;
    }
    else
    {
        ret = -3;
    }

cleanup:
    if (outItems != nullptr)
    {
        CFRelease(outItems);
    }

    CFRelease(cfData);
    return ret;
}

extern "C" int32_t AppleCryptoNative_X509GetRawData(SecCertificateRef cert, CFDataRef* ppDataOut, int32_t* pOSStatus)
{
    if (ppDataOut != nullptr)
        *ppDataOut = nullptr;
    if (pOSStatus != nullptr)
        *pOSStatus = noErr;

    if (cert == nullptr || ppDataOut == nullptr || pOSStatus == nullptr)
        return kErrorBadInput;

    SecExternalFormat dataFormat = kSecFormatX509Cert;
    SecItemImportExportKeyParameters keyParams = {};
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

    *pOSStatus = SecItemExport(cert, dataFormat, 0, &keyParams, ppDataOut);
    return (*pOSStatus == noErr);
}
