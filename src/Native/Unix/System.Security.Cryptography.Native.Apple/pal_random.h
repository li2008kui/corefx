// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

extern "C" int AppleCryptoNative_GetRandomBytes(uint8_t* pBuf, uint32_t cbBuf, int32_t* pkCCStatus);
