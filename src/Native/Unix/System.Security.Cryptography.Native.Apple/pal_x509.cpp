// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509.h"

static const int32_t kErrOutItemsNull = -1;
static const int32_t kErrOutItemsEmpty = -2;

#ifndef DEBUG_LOAD
static int not_printf(const char* format, ...)
{
    (void)format;
    return 0;
}
#define printf not_printf
#endif

extern "C" int32_t
AppleCryptoNative_X509DemuxAndRetainHandle(CFTypeRef handle, SecCertificateRef* pCertOut, SecIdentityRef* pIdentityOut)
{
    if (pCertOut != nullptr)
        *pCertOut = nullptr;
    if (pIdentityOut != nullptr)
        *pIdentityOut = nullptr;

    if (handle == nullptr || pCertOut == nullptr || pIdentityOut == nullptr)
        return kErrorBadInput;

    auto objectType = CFGetTypeID(handle);
    void* nonConstHandle = const_cast<void*>(handle);

    if (objectType == SecIdentityGetTypeID())
    {
        *pIdentityOut = reinterpret_cast<SecIdentityRef>(nonConstHandle);
    }
    else if (objectType == SecCertificateGetTypeID())
    {
        *pCertOut = reinterpret_cast<SecCertificateRef>(nonConstHandle);
    }
    else
    {
        return 0;
    }

    CFRetain(handle);
    return 1;
}

extern "C" int32_t
AppleCryptoNative_X509GetPublicKey(SecCertificateRef cert, SecKeyRef* pPublicKeyOut, int32_t* pOSStatusOut)
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
    else if (osStatus != errSecUnsupportedFormat)
    {
        printf("Call 1: %d\n", osStatus);
    }

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
    else if (osStatus != errSecUnsupportedFormat)
    {
        printf("Call 2: %d\n", osStatus);
    }

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
    else if (osStatus != errSecUnsupportedFormat)
    {
        printf("Call 3: %d\n", osStatus);
    }

    return PAL_X509Unknown;
}

static void ForceLoadPrivateKey(SecIdentityRef identity)
{
    // Exporting the key will cause it to be loaded out of the keychain before
    // we delete the keychain.  And since the same object is kept alive across
    // multiple calls to SecIdentityCopyPrivateKey, this makes it usable to the
    // rest of the process
    SecKeyRef privateKey = nullptr;
    OSStatus local = SecIdentityCopyPrivateKey(identity, &privateKey);

    if (local == noErr)
    {
        SecExternalFormat dataFormat = kSecFormatWrappedPKCS8;
        SecItemImportExportKeyParameters keyParams = {};
        keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
        keyParams.passphrase = CFSTR("ExportPassphrase");

        CFDataRef exported = nullptr;

        SecItemExport(privateKey, dataFormat, 0, &keyParams, &exported);

        CFRelease(keyParams.passphrase);

        if (exported != nullptr)
        {
            CFRelease(exported);
        }
    }

    if (privateKey != nullptr)
    {
        CFRelease(privateKey);
    }
}

static int32_t ProcessCertificateTypeReturn(CFArrayRef items, SecCertificateRef* pCertOut, SecIdentityRef* pIdentityOut)
{
    assert(pCertOut != nullptr && *pCertOut == nullptr);
    assert(pIdentityOut != nullptr && *pIdentityOut == nullptr);

    if (items == nullptr)
    {
        return kErrOutItemsNull;
    }

    CFIndex itemCount = CFArrayGetCount(items);

    if (itemCount == 0)
    {
        return kErrOutItemsEmpty;
    }

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
        CFRetain(bestItem);
        *pIdentityOut = reinterpret_cast<SecIdentityRef>(const_cast<void*>(bestItem));
        ForceLoadPrivateKey(*pIdentityOut);

        return 1;
    }

    return -19;
}

extern "C" int32_t AppleCryptoNative_X509CopyCertFromIdentity(SecIdentityRef identity, SecCertificateRef* pCertOut)
{
    if (pCertOut != nullptr)
        *pCertOut = nullptr;

    // This function handles null inputs for both identity and cert.
    return SecIdentityCopyCertificate(identity, pCertOut);
}

extern "C" int32_t AppleCryptoNative_X509CopyPrivateKeyFromIdentity(SecIdentityRef identity, SecKeyRef* pPrivateKeyOut)
{
    if (pPrivateKeyOut != nullptr)
        *pPrivateKeyOut = nullptr;

    // This function handles null inputs for both identity and key
    return SecIdentityCopyPrivateKey(identity, pPrivateKeyOut);
}

static OSStatus CreateTemporaryKeychain(const char* tempKeychainPath, SecKeychainRef* pKeychainOut)
{
    static const char TemporaryKeychainPassword[] = "DotnetTempKeychain";

    OSStatus status = SecKeychainCreate(
        tempKeychainPath, sizeof(TemporaryKeychainPassword), TemporaryKeychainPassword, false, nullptr, pKeychainOut);

    return status;
}

static int32_t ReadX509(uint8_t* pbData,
                        int32_t cbData,
                        CFStringRef cfPfxPassphrase,
                        char* tempKeychainPath,
                        SecCertificateRef* pCertOut,
                        SecIdentityRef* pIdentityOut,
                        CFArrayRef* pCollectionOut,
                        int32_t* pOSStatus)
{
    assert(pbData != nullptr);
    assert(cbData >= 0);
    assert((pCertOut == nullptr) == (pIdentityOut == nullptr));
    assert((pCertOut == nullptr) != (pCollectionOut == nullptr));

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
    SecKeychainRef tempKeychain = nullptr;

    *pOSStatus = SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, nullptr, nullptr, &outItems);

    if (*pOSStatus == noErr)
    {
        printf("item type: %d, format: %d\n", actualType, dataFormat);

        if (pCollectionOut != nullptr)
        {
            *pCollectionOut = outItems;
            ret = 1;
        }
        else
        {
            ret = ProcessCertificateTypeReturn(outItems, pCertOut, pIdentityOut);
        }
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

        *pOSStatus = CreateTemporaryKeychain(tempKeychainPath, &tempKeychain);

        if (*pOSStatus == noErr)
        {
            *pOSStatus =
                SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, &importParams, tempKeychain, &outItems);
        }

        if (*pOSStatus == errSecPassphraseRequired)
        {
            // Try again with the empty string passphrase.
            printf("pfx: errSecPassphraseRequired\n");
            importParams.passphrase = CFSTR("");

            *pOSStatus =
                SecItemImport(cfData, nullptr, &dataFormat, &actualType, 0, &importParams, tempKeychain, &outItems);

            CFRelease(importParams.passphrase);
            importParams.passphrase = nullptr;
        }
        else if (*pOSStatus == noErr)
            printf("Loaded data with NULL passphrase");

        if (*pOSStatus == noErr)
        {
            printf("pfx item type: %d, format: %d, hadPass: %d\n", actualType, dataFormat, !!cfPfxPassphrase);

            if (pCollectionOut != nullptr)
            {
                *pCollectionOut = outItems;
                ret = 1;
            }
            else
            {
                ret = ProcessCertificateTypeReturn(outItems, pCertOut, pIdentityOut);
            }
        }
        else
        {
            ret = 0;
        }
    }

    if (tempKeychain != nullptr)
    {
        SecKeychainDelete(tempKeychain);
        CFRelease(tempKeychain);
    }

    if (outItems != nullptr && pCollectionOut == nullptr)
    {
        CFRelease(outItems);
    }

    CFRelease(cfData);
    return ret;
}

extern "C" int32_t AppleCryptoNative_X509ImportCollection(uint8_t* pbData,
                                                          int32_t cbData,
                                                          CFStringRef cfPfxPassphrase,
                                                          char* tempKeychainPath,
                                                          CFArrayRef* pCollectionOut,
                                                          int32_t* pOSStatus)
{
    if (pCollectionOut != nullptr)
        *pCollectionOut = nullptr;
    if (pOSStatus != nullptr)
        *pOSStatus = noErr;

    if (pbData == nullptr || cbData < 0 || pCollectionOut == nullptr || pOSStatus == nullptr)
    {
        return kErrorBadInput;
    }

    return ReadX509(pbData, cbData, cfPfxPassphrase, tempKeychainPath, nullptr, nullptr, pCollectionOut, pOSStatus);
}

extern "C" int32_t AppleCryptoNative_X509ImportCertificate(uint8_t* pbData,
                                                           int32_t cbData,
                                                           CFStringRef cfPfxPassphrase,
                                                           char* tempKeychainPath,
                                                           SecCertificateRef* pCertOut,
                                                           SecIdentityRef* pIdentityOut,
                                                           int32_t* pOSStatus)
{
    if (pCertOut != nullptr)
        *pCertOut = nullptr;
    if (pIdentityOut != nullptr)
        *pIdentityOut = nullptr;
    if (pOSStatus != nullptr)
        *pOSStatus = noErr;

    if (pbData == nullptr || cbData < 0 || pCertOut == nullptr || pIdentityOut == nullptr || pOSStatus == nullptr)
    {
        return kErrorBadInput;
    }

    return ReadX509(pbData, cbData, cfPfxPassphrase, tempKeychainPath, pCertOut, pIdentityOut, nullptr, pOSStatus);
}

extern "C" int32_t AppleCryptoNative_X509ExportData(CFArrayRef data,
                                                    PAL_X509ContentType type,
                                                    CFStringRef cfExportPassphrase,
                                                    CFDataRef* pExportOut,
                                                    int32_t* pOSStatus)
{
    if (pExportOut != nullptr)
        *pExportOut = nullptr;
    if (pOSStatus != nullptr)
        *pOSStatus = noErr;

    if (data == nullptr || pExportOut == nullptr || pOSStatus == nullptr)
    {
        return kErrorBadInput;
    }

    SecExternalFormat dataFormat = kSecFormatUnknown;

    switch (type)
    {
        case PAL_Pkcs7:
            dataFormat = kSecFormatPKCS7;
            break;
        case PAL_Pkcs12:
            dataFormat = kSecFormatPKCS12;
            break;
        default:
            return kErrorBadInput;
    }

    SecItemImportExportKeyParameters keyParams = {};
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    keyParams.passphrase = cfExportPassphrase;

    *pOSStatus = SecItemExport(data, dataFormat, 0, &keyParams, pExportOut);

    return *pOSStatus == noErr;
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
