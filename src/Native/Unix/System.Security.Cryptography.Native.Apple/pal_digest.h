// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>

extern "C" void AppleCryptoNative_DigestFree(void* pDigest);
extern "C" CC_SHA1_CTX* AppleCryptoNative_Sha1Create(int32_t* pcbDigest);
extern "C" int AppleCryptoNative_Sha1Update(CC_SHA1_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);
extern "C" int AppleCryptoNative_Sha1Final(CC_SHA1_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
extern "C" CC_SHA256_CTX* AppleCryptoNative_Sha256Create(int32_t* pcbDigest);
extern "C" int AppleCryptoNative_Sha256Update(CC_SHA256_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);
extern "C" int AppleCryptoNative_Sha256Final(CC_SHA256_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha384Create(int32_t* pcbDigest);
extern "C" int AppleCryptoNative_Sha384Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);
extern "C" int AppleCryptoNative_Sha384Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha512Create(int32_t* pcbDigest);
extern "C" int AppleCryptoNative_Sha512Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);
extern "C" int AppleCryptoNative_Sha512Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
extern "C" CC_MD5_CTX* AppleCryptoNative_Md5Create(int32_t* pcbDigest);
extern "C" int AppleCryptoNative_Md5Update(CC_MD5_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);
extern "C" int AppleCryptoNative_Md5Final(CC_MD5_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
