// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include <stdio.h>

extern "C" int32_t AppleCryptoNative_DsaImportEphemeralKey(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, SecKeyRef* ppKeyOut, int32_t* pOSStatus)
{
    if (pbKeyBlob == nullptr || cbKeyBlob < 0 || isPrivateKey < 0 || isPrivateKey > 1 || ppKeyOut == nullptr ||
        pOSStatus == nullptr)
    {
        return kErrorBadInput;
    }

    return kErrorBadInput;
}
