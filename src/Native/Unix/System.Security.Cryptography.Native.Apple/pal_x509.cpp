// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509.h"

static const int32_t kErrOutItemsNull = -1;
static const int32_t kErrOutItemsEmpty = -2;

extern "C" int32_t AppleCryptoNative_X509GetPublicKey(SecCertificateRef cert, SecKeyRef* pPublicKeyOut, int32_t* pOSStatusOut)
{
    if (pPublicKeyOut != nullptr)
        *pPublicKeyOut = nullptr;
    if (pOSStatusOut != nullptr)
        *pOSStatusOut = noErr;

    if (cert == nullptr || pPublicKeyOut == nullptr || pOSStatusOut == nullptr)
        return kErrorBadInput;

    *pOSStatusOut = SecCertificateCopyPublicKey(cert, pPublicKeyOut);
    return (*pOSStatusOut == noErr);
}

extern "C" PAL_X509ContentType AppleCryptoNative_X509GetContentType(uint8_t* pbData, int32_t cbData)
{
    if (pbData == nullptr || cbData < 0)
        return PAL_X509Unknown;

    CFDataRef cfData = CFDataCreateWithBytesNoCopy(nullptr, pbData, cbData, kCFAllocatorNull);

    if (cfData == nullptr)
        return PAL_X509Unknown;

    SecExternalFormat dataFormat = kSecFormatUnknown;
    SecExternalItemType itemType = kSecItemTypeCertificate;
    SecExternalItemType actualType = itemType;

    OSStatus osStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, nullptr);

    printf("Call 1: osStatus (%d), dataFormat (%d), actualType (%d)\n", osStatus, dataFormat, actualType);

    if (osStatus == noErr)
    {
        if (actualType == kSecItemTypeCertificate)
        {
            return PAL_Certificate;
        }
        else if (actualType == kSecItemTypeAggregate)
        {
            if (dataFormat == kSecFormatPKCS7)
            {
                return PAL_Pkcs7;
            }

            if (dataFormat == kSecFormatPKCS12)
            {
                return PAL_Pkcs12;
            }

            printf("DataFormat: %d\n", dataFormat);
        }

        printf("ActualType was not certificate: %d\n", actualType);
    }
    else if (osStatus != errSecUnsupportedFormat) { printf("Call 1: %d\n", osStatus); }

    actualType = kSecItemTypeAggregate;
    dataFormat = kSecFormatPKCS7;

    osStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, nullptr);

    printf("Call 2: osStatus (%d), dataFormat (%d), actualType (%d)\n", osStatus, dataFormat, actualType);

    if (osStatus == noErr)
    {
        if (actualType == kSecItemTypeAggregate && dataFormat == kSecFormatPKCS7)
        {
            return PAL_Pkcs7;
        }

        printf("ActualType (%d), dataFormat (%d)\n", actualType, dataFormat);
    }
    else if (osStatus != errSecUnsupportedFormat) { printf("Call 2: %d\n", osStatus); }

    actualType = kSecItemTypeAggregate;
    dataFormat = kSecFormatPKCS12;

    osStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, nullptr);

    printf("Call 3: osStatus (%d), dataFormat (%d), actualType (%d)\n", osStatus, dataFormat, actualType);

    if (osStatus == noErr || osStatus == errSecPassphraseRequired)
    {
        if (actualType == kSecItemTypeAggregate && dataFormat == kSecFormatPKCS12)
        {
            return PAL_Pkcs12;
        }

        printf("ActualType (%d), dataFormat (%d)\n", actualType, dataFormat);
    }
    else if (osStatus != errSecUnsupportedFormat) { printf("Call 3: %d\n", osStatus); }

    return PAL_X509Unknown;
}

static int32_t ProcessCertificateTypeReturn(SecExternalFormat format, SecExternalItemType type, CFArrayRef items, SecCertificateRef* pCertOut, SecKeyRef* pPrivateKeyOut)
{
    if (format == 3 || type == 2)
        *pPrivateKeyOut = nullptr;

    if (items == nullptr)
    {
        return kErrOutItemsNull;
    }

    CFIndex itemCount = CFArrayGetCount(items);

    if (itemCount == 0)
    {
        return kErrOutItemsEmpty;
    }

    {
        CFTypeRef bestItem = nullptr;

        printf("Dictionary Type: %lu\n", CFDictionaryGetTypeID());
        printf("Certificate Type: %lu\n", SecCertificateGetTypeID());
        printf("Identity Type: %lu\n", SecIdentityGetTypeID());

        for (CFIndex i = 0; i < itemCount; i++)
        {
            CFTypeRef current = CFArrayGetValueAtIndex(items, i);
            auto currentItemType = CFGetTypeID(current);

            printf("Item %lu/%lu: %lu\n", i, itemCount, currentItemType);

            if (currentItemType == SecIdentityGetTypeID())
            {
                bestItem = current;
                break;
            }
            else if (bestItem == nullptr && currentItemType == SecCertificateGetTypeID())
            {
                bestItem = current;
                break;
            }
        }

        if (bestItem == nullptr)
        {
            return -13;
        }

        if (CFGetTypeID(bestItem) == SecCertificateGetTypeID())
        {
            CFRetain(bestItem);
            *pCertOut = reinterpret_cast<SecCertificateRef>(const_cast<void*>(bestItem));
            return 1;
        }

        if (CFGetTypeID(bestItem) == SecIdentityGetTypeID())
        {
            //SecIdentityRef identity = reinterpret_cast<SecIdentityRef>(const_cast<void*>(bestItem));
            *pPrivateKeyOut = nullptr;
        }
    }

    return -19;
}

extern "C" int32_t AppleCryptoNative_X509ImportCertificate(
    uint8_t* pbData, int32_t cbData, CFStringRef cfPfxPassphrase, SecCertificateRef* pCertOut, SecKeyRef* pPrivateKeyOut, int32_t* pOSStatus)
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
    CFArrayRef outItems = nullptr;

    *pOSStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, &outItems);

    if (*pOSStatus == noErr)
    {
        printf("item type: %d, format: %d\n", actualType, dataFormat);
        ret = ProcessCertificateTypeReturn(dataFormat, actualType, outItems, pCertOut, pPrivateKeyOut);
    }
    else
    {
        if (outItems != nullptr)
        {
            CFRelease(outItems);
            outItems = nullptr;
        }

        actualType = kSecItemTypeAggregate;
        dataFormat = kSecFormatPKCS12;
    
        SecItemImportExportKeyParameters importParams = {};
        importParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        importParams.passphrase = cfPfxPassphrase;

        *pOSStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, &importParams, nullptr, &outItems);

        if (*pOSStatus == noErr)
        {
            printf("pfx item type: %d, format: %d, hadPass: %d\n", actualType, dataFormat, !!cfPfxPassphrase);
            ret = ProcessCertificateTypeReturn(dataFormat, actualType, outItems, pCertOut, pPrivateKeyOut);
        }
        else
        {
            ret = 0;
        }
    }

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
