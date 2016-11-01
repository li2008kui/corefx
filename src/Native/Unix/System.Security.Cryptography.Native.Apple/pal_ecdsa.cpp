// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include <stdio.h>

extern "C" int
AppleCryptoNative_EccGenerateKey(int32_t keySizeBits, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus)
{
    if (pPublicKey == nullptr || pPrivateKey == nullptr || pOSStatus == nullptr)
        return kErrorBadInput;

    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(nullptr, 2, &kCFTypeDictionaryKeyCallBacks, nullptr);

    CFNumberRef cfKeySizeValue = CFNumberCreate(nullptr, kCFNumberIntType, &keySizeBits);

    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeEC);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, cfKeySizeValue);

    OSStatus status = SecKeyGeneratePair(attributes, pPublicKey, pPrivateKey);

    CFRelease(attributes);
    CFRelease(cfKeySizeValue);

    *pOSStatus = status;
    return status == noErr;
}

extern "C" int32_t AppleCryptoNative_EccImportEphemeralKey(uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, SecKeyRef* ppKeyOut, int32_t* pOSStatus)
{
    if (pbKeyBlob == nullptr ||
        cbKeyBlob < 0 ||
        isPrivateKey < 0 ||
        isPrivateKey > 1 ||
        ppKeyOut == nullptr ||
        pOSStatus == nullptr)
    {
        return kErrorBadInput;
    }

    int32_t ret = 0;
    CFDataRef cfData = CFDataCreateWithBytesNoCopy(nullptr, pbKeyBlob, cbKeyBlob, kCFAllocatorNull);

    SecExternalFormat dataFormat = kSecFormatOpenSSL;
    SecExternalFormat actualFormat = dataFormat;

    SecExternalItemType itemType = isPrivateKey ? kSecItemTypePrivateKey : kSecItemTypePublicKey;
    SecExternalItemType actualType = itemType;

    CFIndex itemCount;
    CFArrayRef outItems = nullptr;
    CFTypeRef outItem = nullptr;

    *pOSStatus = SecItemImport(
        cfData,
        nullptr,
        &actualFormat,
        &actualType,
        0,
        nullptr,
        nullptr,
        &outItems);

    if (*pOSStatus != noErr)
    {
        ret = 0;
        goto cleanup;
    }

    if (actualFormat != dataFormat ||
        actualType != itemType)
    {
        ret = -2;
        goto cleanup;
    }

    if (outItems == nullptr)
    {
        ret = -3;
        goto cleanup;
    }

    itemCount = CFArrayGetCount(outItems);

    if (itemCount == 0)
    {
        ret = -4;
        goto cleanup;
    }

    if (itemCount > 1)
    {
        ret = -5;
        goto cleanup;
    }

    outItem = CFArrayGetValueAtIndex(outItems, 0);

    if (outItem == nullptr)
    {
        ret = -6;
        goto cleanup;
    }

    if (CFGetTypeID(outItem) != SecKeyGetTypeID())
    {
        ret = -7;
        goto cleanup;
    }

    CFRetain(outItem);
    *ppKeyOut = reinterpret_cast<SecKeyRef>(const_cast<void*>(outItem));
    ret = 1;

cleanup:
    if (outItems != nullptr)
    {
        CFRelease(outItems);
    }

    CFRelease(cfData);
    return ret;
}
