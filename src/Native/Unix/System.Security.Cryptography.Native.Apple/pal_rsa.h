// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"

#include <Security/Security.h>

extern "C" int AppleCryptoNative_RsaGenerateKey(int32_t keySizeBits,
                                                SecKeyRef* pPublicKey,
                                                SecKeyRef* pPrivateKey,
                                                int32_t* pOSStatus);
