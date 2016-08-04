// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>

enum
{
    PAL_HmacSha1,
    PAL_HmacMd5,
    PAL_HmacSha256,
    PAL_HmacSha384,
    PAL_HmacSha512,
};
typedef uint32_t PAL_HmacAlgorithm;

extern "C" void AppleCryptoNative_HmacFree(void* pHmac);
extern "C" CCHmacContext* AppleCryptoNative_HmacCreate(PAL_HmacAlgorithm algorithm, int32_t* pbHmac);
extern "C" int
AppleCryptoNative_HmacInit(CCHmacContext* ctx, PAL_HmacAlgorithm algorithm, uint8_t* pbKey, int32_t cbKey);
extern "C" int AppleCryptoNative_HmacUpdate(CCHmacContext* ctx, uint8_t* pbData, int32_t cbData);
extern "C" int AppleCryptoNative_HmacFinal(CCHmacContext* ctx, uint8_t* pbOutput);
