// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"

int32_t ExecuteCFDataTransform(
    SecTransformRef xform, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    if (xform == nullptr || pbData == nullptr || cbData < 0 || pDataOut == nullptr || pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pDataOut = nullptr;
    *pErrorOut = nullptr;

    CFTypeRef xformOutput = nullptr;
    CFDataRef cfData = nullptr;
    int ret = INT_MIN;

    cfData = CFDataCreateWithBytesNoCopy(nullptr, pbData, cbData, kCFAllocatorNull);

    if (!SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfData, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    xformOutput = SecTransformExecute(xform, pErrorOut);

    if (xformOutput == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (CFGetTypeID(xformOutput) == CFDataGetTypeID())
    {
        CFDataRef cfDataOut = reinterpret_cast<CFDataRef>(const_cast<void*>(xformOutput));
        CFRetain(cfDataOut);
        *pDataOut = cfDataOut;
        ret = 1;
    }
    else
    {
        ret = kErrorUnknownState;
    }

cleanup:
    if (xformOutput != nullptr)
    {
        CFRelease(xformOutput);
    }

    if (cfData != nullptr)
    {
        CFRelease(cfData);
    }

    return ret;
}
