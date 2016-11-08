// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <Security/Security.h>

static const int kErrorBadInput = -1;
static const int kErrorSeeError = -2;
static const int kErrorUnknownAlgorithm = -3;
static const int kErrorUnknownState = -4;

enum
{
    PAL_Asymm_Unknown = 0,
    PAL_RSA = 1,
    PAL_ECC = 2,
    PAL_DSA = 3,
};
typedef uint32_t PAL_AsymmetricKeyType;
