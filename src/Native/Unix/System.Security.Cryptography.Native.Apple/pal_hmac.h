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

/*
Free a CCHmacContext created by AppleCryptoNative_HmacCreate
*/
extern "C" void AppleCryptoNative_HmacFree(void* pHmac);

/*
Create a CCHmacContext for the specified algorithm, receiving the hash output size in pcbHmac.

If *pcbHmac is negative the algorithm is unknown or not supported. If a non-NULL value is returned it should
be freed via AppleCryptoNative_HmacFree regardless of a negative pbHmac value.

Returns NULL on error, an unkeyed CCHmacContext otherwise.
*/
extern "C" CCHmacContext* AppleCryptoNative_HmacCreate(PAL_HmacAlgorithm algorithm, int32_t* pcbHmac);

/*
Initialize an HMAC to the correct key and start state.

Returns 1 on success, 0 on error.
*/
extern "C" int
AppleCryptoNative_HmacInit(CCHmacContext* ctx, PAL_HmacAlgorithm algorithm, uint8_t* pbKey, int32_t cbKey);

/*
Add data into the HMAC

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_HmacUpdate(CCHmacContext* ctx, uint8_t* pbData, int32_t cbData);

/*
Complete the HMAC and copy the result into pbOutput.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_HmacFinal(CCHmacContext* ctx, uint8_t* pbOutput);
