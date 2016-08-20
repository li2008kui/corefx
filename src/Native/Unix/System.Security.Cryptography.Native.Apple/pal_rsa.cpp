// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include <stdio.h>

static int ConfigureSignVerifyTransform(
    SecTransformRef xform,
    CFDataRef cfDataHash,
    CFStringRef cfHashName,
    int hashSize,
    CFErrorRef* pErrorOut)
{
    if (!SecTransformSetAttribute(xform, kSecInputIsAttributeName, kSecInputIsDigest, pErrorOut))
    {
        return 0;
    }

    if (!SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfDataHash, pErrorOut))
    {
        return 0;
    }

    if (!SecTransformSetAttribute(xform, kSecDigestTypeAttribute, cfHashName, pErrorOut))
    {
        return 0;
    }

    if (hashSize != 0)
    {
        CFNumberRef cfHashSize = CFNumberCreate(nullptr, kCFNumberIntType, &hashSize);

        if (!SecTransformSetAttribute(xform, kSecDigestLengthAttribute, cfHashSize, pErrorOut))
        {
            CFRelease(cfHashSize);
            return 0;
        }

        CFRelease(cfHashSize);
    }

    return 1;
}

extern "C" int
AppleCryptoNative_RsaGenerateKey(int32_t keySizeBits, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus)
{
    if (pPublicKey == nullptr || pPrivateKey == nullptr || pOSStatus == nullptr)
        return -1;
    if (keySizeBits < 384 || keySizeBits > 16384)
        return -2;

    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(nullptr, 2, &kCFTypeDictionaryKeyCallBacks, nullptr);

    CFNumberRef cfKeySizeValue = CFNumberCreate(nullptr, kCFNumberIntType, &keySizeBits);

    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, cfKeySizeValue);

    OSStatus status = SecKeyGeneratePair(attributes, pPublicKey, pPrivateKey);

    CFRelease(attributes);
    CFRelease(cfKeySizeValue);

    *pOSStatus = status;
    return status == noErr;
}

extern "C" int32_t AppleCryptoNative_RsaImportEphemeralKey(uint8_t* pbPkcs1Key, int32_t cbPkcs1Key, int32_t isPrivateKey, SecKeyRef* ppKeyOut, int32_t* pOSStatus)
{
    if (pbPkcs1Key == nullptr ||
        cbPkcs1Key < 0 ||
        isPrivateKey < 0 ||
        isPrivateKey > 1 ||
        ppKeyOut == nullptr ||
        pOSStatus == nullptr)
    {
        return -1;
    }

    int32_t ret = 0;
    CFDataRef cfData = CFDataCreateWithBytesNoCopy(nullptr, pbPkcs1Key, cbPkcs1Key, kCFAllocatorNull);
    //CFDataRef cfData = CFDataCreate(nullptr, pbPkcs1Key, cbPkcs1Key);

    // RSA PKCS#1 blobs
    SecExternalFormat dataFormat = isPrivateKey ? kSecFormatOpenSSL : kSecFormatBSAFE;
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

extern "C" uint64_t AppleCryptoNative_RsaGetKeySizeInBytes(SecKeyRef publicKey)
{
    if (publicKey == nullptr)
    {
        return 0;
    }

    return SecKeyGetBlockSize(publicKey);
}

extern "C" int32_t AppleCryptoNative_RsaExportKey(SecKeyRef pKey, int32_t exportPrivate, CFDataRef* ppDataOut, int32_t* pOSStatus)
{
    if (pKey == nullptr ||
        ppDataOut == nullptr ||
        pOSStatus == nullptr)
    {
        return -1;
    }

    SecExternalFormat dataFormat = kSecFormatOpenSSL;
    SecItemImportExportKeyParameters keyParams = {};
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;

    if (exportPrivate)
    {
        // CFSTR requires a string literal, and does not need to be CFRelease()d.
        CFStringRef cfExportPassphrase = CFSTR("passphrase");
        keyParams.passphrase = cfExportPassphrase;
        dataFormat = kSecFormatWrappedPKCS8;
    }

    *pOSStatus = SecItemExport(
        pKey,
        dataFormat,
        0,
        &keyParams,
        ppDataOut);

    return (*pOSStatus == noErr);
}

extern "C" int AppleCryptoNative_RsaSign(SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, PAL_HashAlgorithm hashAlgorithm, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    const int kErrorBadInput = -1;
    const int kErrorSeeError= -2;
    const int kErrorUnknownAlgorithm = -3;
    const int kErrorUnknownState = -4;

    if (privateKey == nullptr ||
        pbDataHash == nullptr ||
        cbDataHash < 0 ||
        pSignatureOut == nullptr ||
        pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pErrorOut = nullptr;
    *pSignatureOut = nullptr;

    CFStringRef cfHashName = nullptr;
    int hashSize = 0;

    switch (hashAlgorithm)
    {
        case PAL_MD5:
            cfHashName = kSecDigestMD5;
            break;
        case PAL_SHA1:
            cfHashName = kSecDigestSHA1;
            break;
        case PAL_SHA256:
            cfHashName = kSecDigestSHA2;
            hashSize = 256;
            break;
        case PAL_SHA384:
            cfHashName = kSecDigestSHA2;
            hashSize = 384;
            break;
        case PAL_SHA512:
            cfHashName = kSecDigestSHA2;
            hashSize = 512;
            break;
        default:
            return kErrorUnknownAlgorithm;;
    }

    int ret = INT_MIN;
    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(nullptr, pbDataHash, cbDataHash, kCFAllocatorNull);
    SecTransformRef signer = SecSignTransformCreate(privateKey, pErrorOut);
    CFTypeRef signerResponse = nullptr;
    CFDataRef signature = nullptr;

    if (signer == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (!ConfigureSignVerifyTransform(signer, dataHash, cfHashName, hashSize, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    signerResponse = SecTransformExecute(signer, pErrorOut);

    if (signerResponse == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (CFGetTypeID(signerResponse) != CFDataGetTypeID())
    {
        ret = kErrorUnknownState;
        goto cleanup;
    }

    signature = reinterpret_cast<CFDataRef>(const_cast<void*>(signerResponse));

    if (CFDataGetLength(signature) > 0)
    {
        // We're going to call CFRelease in cleanup, so this keeps it alive
        // to be interpreted by the managed code.
        CFRetain(signature);
        *pSignatureOut = signature;
        ret = 1;
    }
    else
    {
        ret = kErrorUnknownState;
    }

cleanup:
    if (signerResponse != nullptr)
    {
        CFRelease(signerResponse);
    }

    if (signer != nullptr)
    {
        CFRelease(signer);
    }

    CFRelease(dataHash);
    return ret;
}

extern "C" int AppleCryptoNative_RsaVerify(SecKeyRef publicKey, uint8_t* pbDataHash, int32_t cbDataHash, uint8_t* pbSignature, int32_t cbSignature, PAL_HashAlgorithm hashAlgorithm, CFErrorRef* pErrorOut)
{
    const int kErrorBadInput = -1;
    const int kErrorSeeError= -2;
    const int kErrorUnknownAlgorithm = -3;

    if (publicKey == nullptr ||
        pbDataHash == nullptr ||
        cbDataHash < 0 ||
        pbSignature == nullptr ||
        cbSignature < 0 ||
        pErrorOut == nullptr)
        return kErrorBadInput;

    *pErrorOut = nullptr;
    int hashSize = 0;
    CFStringRef cfHashName;

    switch (hashAlgorithm)
    {
        case PAL_MD5:
            cfHashName = kSecDigestMD5;
            break;
        case PAL_SHA1:
            cfHashName = kSecDigestSHA1;
            break;
        case PAL_SHA256:
            cfHashName = kSecDigestSHA2;
            hashSize = 256;
            break;
        case PAL_SHA384:
            cfHashName = kSecDigestSHA2;
            hashSize = 384;
            break;
        case PAL_SHA512:
            cfHashName = kSecDigestSHA2;
            hashSize = 512;
            break;
        default:
            return kErrorUnknownAlgorithm;;
    }

    int ret = INT_MIN;
    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(nullptr, pbDataHash, cbDataHash, kCFAllocatorNull);
    CFDataRef signature = CFDataCreateWithBytesNoCopy(nullptr, pbSignature, cbSignature, kCFAllocatorNull);
    SecTransformRef verifier = SecVerifyTransformCreate(publicKey, signature, pErrorOut);
    CFTypeRef verifierResponse = nullptr;

    if (verifier == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (!ConfigureSignVerifyTransform(verifier, dataHash, cfHashName, hashSize, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    verifierResponse = SecTransformExecute(verifier, pErrorOut);

    if (verifierResponse == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = (verifierResponse == kCFBooleanTrue);

cleanup:

    if (verifierResponse != nullptr)
    {
        CFRelease(verifierResponse);
    }

    if (verifier != nullptr)
    {
        CFRelease(verifier);
    }

    CFRelease(dataHash);
    CFRelease(signature);

    return ret;
}
