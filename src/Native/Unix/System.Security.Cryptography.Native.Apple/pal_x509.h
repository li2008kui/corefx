// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"

#include <Security/Security.h>

enum
{
    PAL_X509Unknown = 0,
    PAL_Certificate = 1,
    PAL_SerializedCert = 2,
    PAL_Pkcs12 = 3,
    PAL_SerializedStore = 4,
    PAL_Pkcs7 = 5,
    PAL_Authenticode = 6,
};
typedef uint32_t PAL_X509ContentType;
