// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_types.h"

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonHMAC.h>

/*
Free a CC_[Algorithm]_CTX*
*/
extern "C" void AppleCryptoNative_DigestFree(void* pDigest);

/*
Create a CC_SHA1_CTX for performing SHA-1 hashes

Returns NULL on error, otherwise returns a ready-to-go CC_SHA1_CTX and outputs the hash size in pcbDigest.
*/
extern "C" CC_SHA1_CTX* AppleCryptoNative_Sha1Create(int32_t* pcbDigest);

/*
Shims CC_SHA1_Update

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha1Update(CC_SHA1_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);

/*
Copies the hash output into pBuf and resets the hash state.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha1Final(CC_SHA1_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);

/*
Create a CC_SHA256_CTX for performing SHA-2-256 hashes

Returns NULL on error, otherwise returns a ready-to-go CC_SHA256_CTX and outputs the hash size in pcbDigest.
*/
extern "C" CC_SHA256_CTX* AppleCryptoNative_Sha256Create(int32_t* pcbDigest);

/*
Shims CC_SHA256_Update

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha256Update(CC_SHA256_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);

/*
Copies the hash output into pBuf and resets the hash state.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha256Final(CC_SHA256_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);

/*
Create a CC_SHA512_CTX for performing SHA-2-384 hashes.

A CC_SHA512_CTX is used for SHA384 because SHA384 is a truncated form of SHA512 with a different start state;
but since the space requirement is the same as for SHA512 the structure is reused between them.

Returns NULL on error, otherwise returns a ready-to-go CC_SHA512_CTX and outputs the hash size in pcbDigest.
*/
extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha384Create(int32_t* pcbDigest);

/*
Shims CC_SHA384_Update

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha384Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);

/*
Copies the hash output into pBuf and resets the hash state.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha384Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);

/*
Create a CC_SHA512_CTX for performing SHA-2-512 hashes

Returns NULL on error, otherwise returns a ready-to-go CC_SHA512_CTX and outputs the hash size in pcbDigest.
*/
extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha512Create(int32_t* pcbDigest);

/*
Shims CC_SHA512_Update

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha512Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);

/*
Copies the hash output into pBuf and resets the hash state.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Sha512Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);

/*
Create a CC_MD5_CTX for performing MD5 hashes

Returns NULL on error, otherwise returns a ready-to-go CC_MD5_CTX and outputs the hash size in pcbDigest.
*/
extern "C" CC_MD5_CTX* AppleCryptoNative_Md5Create(int32_t* pcbDigest);

/*
Shims CC_MD5_Update

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Md5Update(CC_MD5_CTX* ctx, uint8_t* pBuf, int32_t cbBuf);

/*
Copies the hash output into pBuf and resets the hash state.

Returns 1 on success, 0 on error.
*/
extern "C" int AppleCryptoNative_Md5Final(CC_MD5_CTX* ctx, uint8_t* pOutput, int32_t cbOutput);
