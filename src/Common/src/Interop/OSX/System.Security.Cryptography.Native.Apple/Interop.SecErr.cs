// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern SafeCFStringHandle AppleCryptoNative_SecCopyErrorMessageString(int osStatus);

        internal static Exception CreateExceptionForOSStatus(int osStatus)
        {
            using (SafeCFStringHandle cfString = AppleCryptoNative_SecCopyErrorMessageString(osStatus))
            {
                if (cfString.IsInvalid)
                {
                    return CreateExceptionForCCError(osStatus, "OSStatus");
                }

                string msg = CoreFoundation.CFStringToString(cfString);
                return new AppleCommonCryptoCryptographicException(osStatus, msg);
            }
        }
    }
}
