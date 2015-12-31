// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "pal_eckey.h"

#include <assert.h>
#include <openssl/objects.h>

extern "C" void EcKeyDestroy(EC_KEY* r)
{
    EC_KEY_free(r);
}

extern "C" EC_KEY* EcKeyCreateByCurveName(int32_t nid)
{
    return EC_KEY_new_by_curve_name(nid);
}

extern "C" EC_KEY* EcKeyCreateForCurve(const EC_GROUP* curve)
{
    if (curve == nullptr)
    {
        return nullptr;
    }

    EC_KEY* key = EC_KEY_new();

    if (key == nullptr)
    {
        return nullptr;
    }

    if (!EC_KEY_set_group(key, curve))
    {
        EC_KEY_free(key);
        return nullptr;
    }

    return key;
}

extern "C" int32_t EcKeyGenerateKey(EC_KEY* eckey)
{
    return EC_KEY_generate_key(eckey);
}

extern "C" int32_t EcKeyUpRef(EC_KEY* r)
{
    return EC_KEY_up_ref(r);
}

extern "C" int32_t EcKeyGetCurveName(const EC_KEY* key)
{
    if (key == nullptr)
    {
        return NID_undef;
    }

    const EC_GROUP* group = EC_KEY_get0_group(key);
    if (group == nullptr)
    {
        return NID_undef;
    }

    return EC_GROUP_get_curve_name(group);
}

extern "C" void EcGroupDestroy(EC_GROUP* g)
{
    EC_GROUP_free(g);
}

extern "C" EC_GROUP* EcGroupCreatePrimeCurve(
    uint8_t* prime,
    int32_t primeLen,
    uint8_t* a,
    int32_t aLen,
    uint8_t* b,
    int32_t bLen,
    uint8_t* gx,
    int32_t gxLen,
    uint8_t* gy,
    int32_t gyLen,
    uint8_t* order,
    int32_t orderLen,
    uint8_t* cofactor,
    int32_t cofactorLen)
{
    if (prime == nullptr || primeLen <= 0 ||
        a == nullptr || aLen <= 0 ||
        b == nullptr || bLen <= 0 ||
        gx == nullptr || gxLen <= 0 ||
        gy == nullptr || gyLen <= 0 ||
        order == nullptr || orderLen <= 0 ||
        cofactor == nullptr || cofactorLen <= 0)
    {
        return nullptr;
    }

    BIGNUM* bnPrime = nullptr;
    BIGNUM* bnA = nullptr;
    BIGNUM* bnB = nullptr;
    BIGNUM* bnGx = nullptr;
    BIGNUM* bnGy = nullptr;
    BIGNUM* bnOrder = nullptr;
    BIGNUM* bnCofactor = nullptr;
    EC_GROUP* ret = nullptr;
    EC_POINT* generator = nullptr;

    if ((bnPrime = BN_bin2bn(prime, primeLen, nullptr)) == nullptr ||
        (bnA = BN_bin2bn(a, aLen, nullptr)) == nullptr ||
        (bnB = BN_bin2bn(b, bLen, nullptr)) == nullptr ||
        (bnGx = BN_bin2bn(gx, gxLen, nullptr)) == nullptr ||
        (bnGy = BN_bin2bn(gy, gyLen, nullptr)) == nullptr ||
        (bnOrder = BN_bin2bn(order, orderLen, nullptr)) == nullptr ||
        (bnCofactor = BN_bin2bn(cofactor, cofactorLen, nullptr)) == nullptr)
    {
        goto err;
    }

    // EC_GROUP_new_curve_GFp makes a copy of the BIGNUM values, so our versions
    // still need to be freed.
    if ((ret = EC_GROUP_new_curve_GFp(bnPrime, bnA, bnB, nullptr)) == nullptr)
    {
        goto err;
    }

    // Now that ret is set, if anything goes wrong we need to EC_GROUP_free it,
    // and set it to nullptr.

    if ((generator = EC_POINT_new(ret)) == nullptr ||
        !EC_POINT_set_affine_coordinates_GFp(ret, generator, bnGx, bnGy, nullptr) ||
        !EC_GROUP_set_generator(ret, generator, bnOrder, bnCofactor))
    {
        EC_GROUP_free(ret);
        ret = nullptr;
        goto err;
    }

err:
    if (bnPrime != nullptr)
        BN_free(bnPrime);
    if (bnA != nullptr)
        BN_free(bnA);
    if (bnB != nullptr)
        BN_free(bnB);
    if (bnGx != nullptr)
        BN_free(bnGx);
    if (bnGy != nullptr)
        BN_free(bnGy);
    if (bnOrder != nullptr)
        BN_free(bnOrder);
    if (bnCofactor != nullptr)
        BN_free(bnCofactor);
    if (generator != nullptr)
        EC_POINT_free(generator);

    return ret;
}

extern "C" int32_t EcGetKnownCurveNids(int32_t* nids, int32_t cNids)
{
    size_t totalCurves = EC_get_builtin_curves(nullptr, 0);

    if (nids == nullptr || cNids == 0)
    {
        return int32_t(totalCurves);
    }

    size_t nitems = size_t(cNids);

    if (nitems < totalCurves)
    {
        return -1;
    }

    EC_builtin_curve* curves = static_cast<EC_builtin_curve*>(malloc((sizeof(EC_builtin_curve) * totalCurves)));

    if (curves == nullptr)
    {
        return -2;
    }

    size_t returned = EC_get_builtin_curves(curves, nitems);
    assert(returned == totalCurves);

    for (size_t i = 0; i < totalCurves; ++i)
    {
        nids[i] = curves[i].nid;
    }

    free(curves);
    return int32_t(returned);
}
