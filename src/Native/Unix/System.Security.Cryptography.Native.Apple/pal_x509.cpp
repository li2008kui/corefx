// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509.h"


extern "C" int32_t AppleCrypto_GetX509RawData(SecCertificateRef cert, CFDataRef* pDataOut)
{
    if (pDataOut != nullptr)
        *pDataOut = nullptr;

    if (cert == nullptr || pDataOut == nullptr)
        return kErrorBadInput;

    return kErrorUnknownState;
}
