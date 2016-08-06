// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <stdio.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonCryptor.h>

enum
{
	PAL_OperationEncrypt = 0,
	PAL_OperationDecrypt = 1,
};
typedef uint32_t PAL_SymmetricOperation;

enum
{
	PAL_AlgorithmAES = 0,
	PAL_Algorithm3DES = 2,
};
typedef uint32_t PAL_SymmetricAlgorithm;

enum
{
	PAL_ChainingModeECB = 1,
	PAL_ChainingModeCBC = 2,
};
typedef uint32_t PAL_ChainingMode;

enum
{
	PAL_PaddingModeNone = 0,
	PAL_PaddingModePkcs7 = 1,
};
typedef uint32_t PAL_PaddingMode;

// Pre-defined for future expansion.
// CryptorCreateWithMode accepts an option to define CTR mode as little-endian or big-endian,
// and may in the future define other options.
// So as to avoid changing the function signature in the future, the enum shell is being
// declared now.
enum
{
	PAL_SymmetricOptions_None = 0,
};
typedef uint32_t PAL_SymmetricOptions;


extern "C" void AppleCryptoNative_CryptorFree(CCCryptorRef cryptor);

extern "C" int AppleCryptoNative_CryptorCreate(
	PAL_SymmetricOperation operation,
	PAL_SymmetricAlgorithm algorithm,
	PAL_ChainingMode chainingMode,
	PAL_PaddingMode paddingMode,
	const uint8_t* pbKey,
	int32_t cbKey,
	const uint8_t* pbIv,
	PAL_SymmetricOptions options,
	CCCryptorRef* ppCryptorOut,
	int32_t* pkCCStatus);

extern "C" int AppleCryptoNative_CryptorUpdate(
	CCCryptorRef cryptor,
	const uint8_t* pbData,
	int32_t cbData,
	uint32_t* pbOutput,
	int32_t cbOutput,
	int32_t* pcbWritten,
	int32_t* pkCCStatus);

extern "C" int AppleCryptoNative_CryptorFinal(
	CCCryptorRef cryptor,
	uint8_t* pbOutput,
	int32_t cbOutput,
	int32_t* pcbWritten,
	int32_t* pkCCStatus);

extern "C" int AppleCryptoNative_CryptorReset(
	CCCryptorRef cryptor,
	const uint8_t* pbIv,
	int32_t* pkCCStatus);
