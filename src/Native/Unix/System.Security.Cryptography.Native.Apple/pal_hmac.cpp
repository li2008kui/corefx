// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_hmac.h"

static_assert(PAL_HmacSha1 == kCCHmacAlgSHA1, "");
static_assert(PAL_HmacMd5 == kCCHmacAlgMD5, "");
static_assert(PAL_HmacSha256 == kCCHmacAlgSHA256, "");
static_assert(PAL_HmacSha384 == kCCHmacAlgSHA384, "");
static_assert(PAL_HmacSha512 == kCCHmacAlgSHA512, "");

extern "C" void AppleCryptoNative_HmacFree(void* pHmac)
{
    if (pHmac != nullptr)
    {
        free(pHmac);
    }
}

static int GetHmacOutputSize(PAL_HmacAlgorithm algorithm)
{
    switch (algorithm)
    {
        case PAL_HmacSha1:
            return CC_SHA1_DIGEST_LENGTH;
        case PAL_HmacMd5:
            return CC_MD5_DIGEST_LENGTH;
        case PAL_HmacSha256:
            return CC_SHA256_DIGEST_LENGTH;
        case PAL_HmacSha384:
            return CC_SHA384_DIGEST_LENGTH;
        case PAL_HmacSha512:
            return CC_SHA512_DIGEST_LENGTH;
        default:
            return -1;
    }
}

extern "C" CCHmacContext* AppleCryptoNative_HmacCreate(PAL_HmacAlgorithm algorithm, int32_t* pbHmac)
{
    if (pbHmac == nullptr)
        return nullptr;

    *pbHmac = GetHmacOutputSize(algorithm);
    return reinterpret_cast<CCHmacContext*>(malloc(sizeof(CCHmacContext)));
}

extern "C" int
AppleCryptoNative_HmacInit(CCHmacContext* ctx, PAL_HmacAlgorithm algorithm, uint8_t* pbKey, int32_t cbKey)
{
    if (ctx == nullptr || cbKey < 0)
        return 0;
    if (cbKey != 0 && pbKey == nullptr)
        return 0;

    // No return value
    CCHmacInit(ctx, algorithm, pbKey, static_cast<size_t>(cbKey));
    return 1;
}

extern "C" int AppleCryptoNative_HmacUpdate(CCHmacContext* ctx, uint8_t* pbData, int32_t cbData)
{
    if (cbData == 0)
        return 1;
    if (ctx == nullptr || pbData == nullptr)
        return 0;

    // No return value
    CCHmacUpdate(ctx, pbData, static_cast<size_t>(cbData));
    return 1;
}

extern "C" int AppleCryptoNative_HmacFinal(CCHmacContext* ctx, uint8_t* pbOutput)
{
    if (ctx == nullptr || pbOutput == nullptr)
        return 0;

    // No return value
    CCHmacFinal(ctx, pbOutput);
    return 1;
}
