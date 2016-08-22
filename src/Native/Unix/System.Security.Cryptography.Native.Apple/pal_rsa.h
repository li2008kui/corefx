// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <Security/Security.h>

enum
{
    PAL_Unknown = 0,
    PAL_MD5,
    PAL_SHA1,
    PAL_SHA256,
    PAL_SHA384,
    PAL_SHA512,
};
typedef uint32_t PAL_HashAlgorithm;

extern "C" int
AppleCryptoNative_RsaGenerateKey(int32_t keySizeBits, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus);
