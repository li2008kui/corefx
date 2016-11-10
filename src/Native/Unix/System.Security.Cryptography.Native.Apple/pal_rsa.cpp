// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include <stdio.h>

int32_t ExecuteCFDataTransform(
    SecTransformRef xform, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

extern "C" int
AppleCryptoNative_RsaGenerateKey(int32_t keySizeBits, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus)
{
    if (pPublicKey == nullptr || pPrivateKey == nullptr || pOSStatus == nullptr)
        return kErrorBadInput;
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

extern "C" int32_t
AppleCryptoNative_RsaExportKey(SecKeyRef pKey, int32_t exportPrivate, CFDataRef* ppDataOut, int32_t* pOSStatus)
{
    if (pKey == nullptr || ppDataOut == nullptr || pOSStatus == nullptr)
    {
        return kErrorBadInput;
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

    *pOSStatus = SecItemExport(pKey, dataFormat, 0, &keyParams, ppDataOut);

    return (*pOSStatus == noErr);
}

int32_t ExecuteOaepTransform(SecTransformRef xform,
                             uint8_t* pbData,
                             int32_t cbData,
                             PAL_HashAlgorithm algorithm,
                             CFDataRef* pDataOut,
                             CFErrorRef* pErrorOut)
{
    int ret = INT_MIN;

    if (!SecTransformSetAttribute(xform, kSecPaddingKey, kSecPaddingOAEPKey, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    // TODO: set kSecOAEPMGF1DigestAlgorithmAttributeName as appropriate.
    // TODO: How does it do OAEP-SHA256?
    if (algorithm != PAL_SHA1)
    {
        ret = kErrorUnknownAlgorithm;
        goto cleanup;
    }

    ret = ExecuteCFDataTransform(xform, pbData, cbData, pDataOut, pErrorOut);

cleanup:
    return ret;
}

extern "C" int32_t AppleCryptoNative_RsaDecryptOaep(SecKeyRef privateKey,
                                                    uint8_t* pbData,
                                                    int32_t cbData,
                                                    PAL_HashAlgorithm mfgAlgorithm,
                                                    CFDataRef* pDecryptedOut,
                                                    CFErrorRef* pErrorOut)
{
    if (privateKey == nullptr || pbData == nullptr || cbData < 0 || pDecryptedOut == nullptr || pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pDecryptedOut = nullptr;
    *pErrorOut = nullptr;

    int ret = INT_MIN;
    SecTransformRef decryptor = SecDecryptTransformCreate(privateKey, pErrorOut);

    if (decryptor == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteOaepTransform(decryptor, pbData, cbData, mfgAlgorithm, pDecryptedOut, pErrorOut);

cleanup:

    if (decryptor != nullptr)
    {
        CFRelease(decryptor);
    }

    return ret;
}

extern "C" int32_t AppleCryptoNative_RsaDecryptPkcs(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut)
{
    if (privateKey == nullptr || pbData == nullptr || cbData < 0 || pDecryptedOut == nullptr || pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pDecryptedOut = nullptr;
    *pErrorOut = nullptr;

    int ret = INT_MIN;
    SecTransformRef decryptor = SecDecryptTransformCreate(privateKey, pErrorOut);

    if (decryptor == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteCFDataTransform(decryptor, pbData, cbData, pDecryptedOut, pErrorOut);

cleanup:

    if (decryptor != nullptr)
    {
        CFRelease(decryptor);
    }

    return ret;
}

extern "C" int32_t AppleCryptoNative_RsaEncryptOaep(SecKeyRef publicKey,
                                                    uint8_t* pbData,
                                                    int32_t cbData,
                                                    PAL_HashAlgorithm mgfAlgorithm,
                                                    CFDataRef* pEncryptedOut,
                                                    CFErrorRef* pErrorOut)
{
    if (publicKey == nullptr || pbData == nullptr || cbData < 0 || pEncryptedOut == nullptr || pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pEncryptedOut = nullptr;
    *pErrorOut = nullptr;

    int ret = INT_MIN;
    SecTransformRef encryptor = SecEncryptTransformCreate(publicKey, pErrorOut);

    if (encryptor == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteOaepTransform(encryptor, pbData, cbData, mgfAlgorithm, pEncryptedOut, pErrorOut);

cleanup:

    if (encryptor != nullptr)
    {
        CFRelease(encryptor);
    }

    return ret;
}

extern "C" int32_t AppleCryptoNative_RsaEncryptPkcs(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut)
{
    if (publicKey == nullptr || pbData == nullptr || cbData < 0 || pEncryptedOut == nullptr || pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pEncryptedOut = nullptr;
    *pErrorOut = nullptr;

    int ret = INT_MIN;
    SecTransformRef encryptor = SecEncryptTransformCreate(publicKey, pErrorOut);

    if (encryptor == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteCFDataTransform(encryptor, pbData, cbData, pEncryptedOut, pErrorOut);

cleanup:

    if (encryptor != nullptr)
    {
        CFRelease(encryptor);
    }

    return ret;
}
