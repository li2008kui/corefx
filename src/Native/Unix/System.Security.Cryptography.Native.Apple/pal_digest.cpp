// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_types.h"

#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>

extern "C" void AppleCryptoNative_DigestFree(void* pDigest)
{
    if (pDigest != nullptr)
    {
        free(pDigest);
    }
}

extern "C" CC_SHA1_CTX* AppleCryptoNative_Sha1Create(int32_t* pcbDigest)
{
    if (pcbDigest == nullptr)
    {
        return nullptr;
    }

    *pcbDigest = CC_SHA1_DIGEST_LENGTH;
    CC_SHA1_CTX* ctx = reinterpret_cast<CC_SHA1_CTX*>(malloc(sizeof(CC_SHA1_CTX)));
    CC_SHA1_Init(ctx);
    return ctx;
}

extern "C" int AppleCryptoNative_Sha1Update(CC_SHA1_CTX* ctx, uint8_t* pBuf, int32_t cbBuf)
{
    if (cbBuf == 0)
        return 1;
    if (ctx == nullptr || pBuf == nullptr)
        return 0;

    return CC_SHA1_Update(ctx, pBuf, static_cast<CC_LONG>(cbBuf));
}

extern "C" int AppleCryptoNative_Sha1Final(CC_SHA1_CTX* ctx, uint8_t* pOutput, int32_t cbOutput)
{
    if (ctx == nullptr || pOutput == nullptr || cbOutput < CC_SHA1_DIGEST_LENGTH)
        return 0;

    int ret = CC_SHA1_Final(pOutput, ctx);

    if (!ret)
    {
        return ret;
    }

    return CC_SHA1_Init(ctx);
}

extern "C" CC_SHA256_CTX* AppleCryptoNative_Sha256Create(int32_t* pcbDigest)
{
    if (pcbDigest == nullptr)
    {
        return nullptr;
    }

    *pcbDigest = CC_SHA256_DIGEST_LENGTH;
    CC_SHA256_CTX* ctx = reinterpret_cast<CC_SHA256_CTX*>(malloc(sizeof(CC_SHA256_CTX)));
    CC_SHA256_Init(ctx);
    return ctx;
}

extern "C" int AppleCryptoNative_Sha256Update(CC_SHA256_CTX* ctx, uint8_t* pBuf, int32_t cbBuf)
{
    if (cbBuf == 0)
        return 1;
    if (ctx == nullptr || pBuf == nullptr)
        return 0;

    return CC_SHA256_Update(ctx, pBuf, static_cast<CC_LONG>(cbBuf));
}

extern "C" int AppleCryptoNative_Sha256Final(CC_SHA256_CTX* ctx, uint8_t* pOutput, int32_t cbOutput)
{
    if (ctx == nullptr || pOutput == nullptr || cbOutput < CC_SHA256_DIGEST_LENGTH)
        return 0;

    int ret = CC_SHA256_Final(pOutput, ctx);

    if (!ret)
    {
        return ret;
    }

    return CC_SHA256_Init(ctx);
}

extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha384Create(int32_t* pcbDigest)
{
    if (pcbDigest == nullptr)
    {
        return nullptr;
    }

    *pcbDigest = CC_SHA384_DIGEST_LENGTH;
    CC_SHA512_CTX* ctx = reinterpret_cast<CC_SHA512_CTX*>(malloc(sizeof(CC_SHA512_CTX)));
    CC_SHA384_Init(ctx);
    return ctx;
}

extern "C" int AppleCryptoNative_Sha384Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf)
{
    if (cbBuf == 0)
        return 1;
    if (ctx == nullptr || pBuf == nullptr)
        return 0;

    return CC_SHA384_Update(ctx, pBuf, static_cast<CC_LONG>(cbBuf));
}

extern "C" int AppleCryptoNative_Sha384Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput)
{
    if (ctx == nullptr || pOutput == nullptr || cbOutput < CC_SHA384_DIGEST_LENGTH)
        return 0;

    int ret = CC_SHA384_Final(pOutput, ctx);

    if (!ret)
    {
        return ret;
    }

    return CC_SHA384_Init(ctx);
}

extern "C" CC_SHA512_CTX* AppleCryptoNative_Sha512Create(int32_t* pcbDigest)
{
    if (pcbDigest == nullptr)
    {
        return nullptr;
    }

    *pcbDigest = CC_SHA512_DIGEST_LENGTH;
    CC_SHA512_CTX* ctx = reinterpret_cast<CC_SHA512_CTX*>(malloc(sizeof(CC_SHA512_CTX)));
    CC_SHA512_Init(ctx);
    return ctx;
}

extern "C" int AppleCryptoNative_Sha512Update(CC_SHA512_CTX* ctx, uint8_t* pBuf, int32_t cbBuf)
{
    if (cbBuf == 0)
        return 1;
    if (ctx == nullptr || pBuf == nullptr)
        return 0;

    return CC_SHA512_Update(ctx, pBuf, static_cast<CC_LONG>(cbBuf));
}

extern "C" int AppleCryptoNative_Sha512Final(CC_SHA512_CTX* ctx, uint8_t* pOutput, int32_t cbOutput)
{
    if (ctx == nullptr || pOutput == nullptr || cbOutput < CC_SHA512_DIGEST_LENGTH)
        return 0;

    int ret = CC_SHA512_Final(pOutput, ctx);

    if (!ret)
    {
        return ret;
    }

    return CC_SHA512_Init(ctx);
}

extern "C" CC_MD5_CTX* AppleCryptoNative_Md5Create(int32_t* pcbDigest)
{
    if (pcbDigest == nullptr)
    {
        return nullptr;
    }

    *pcbDigest = CC_MD5_DIGEST_LENGTH;
    CC_MD5_CTX* ctx = reinterpret_cast<CC_MD5_CTX*>(malloc(sizeof(CC_MD5_CTX)));
    CC_MD5_Init(ctx);
    return ctx;
}

extern "C" int AppleCryptoNative_Md5Update(CC_MD5_CTX* ctx, uint8_t* pBuf, int32_t cbBuf)
{
    if (cbBuf == 0)
        return 1;
    if (ctx == nullptr || pBuf == nullptr)
        return 0;

    return CC_MD5_Update(ctx, pBuf, static_cast<CC_LONG>(cbBuf));
}

extern "C" int AppleCryptoNative_Md5Final(CC_MD5_CTX* ctx, uint8_t* pOutput, int32_t cbOutput)
{
    if (ctx == nullptr || pOutput == nullptr || cbOutput < CC_MD5_DIGEST_LENGTH)
        return 0;

    int ret = CC_MD5_Final(pOutput, ctx);

    if (!ret)
    {
        return ret;
    }

    return CC_MD5_Init(ctx);
}
