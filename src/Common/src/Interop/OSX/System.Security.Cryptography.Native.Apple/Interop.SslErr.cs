// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SafeSslHandle = System.Net.SafeSslHandle;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        internal class SslException : Exception
        {
            internal SslException()
            {
            }

            internal SslException(int errorCode, string message)
                : base(message)
            {
                HResult = errorCode;
            }
        }
    }

    internal static partial class AppleCrypto
    {
        internal static Exception CreateExceptionForOSStatus(int osStatus)
        {
            using (SafeCFStringHandle cfString = AppleCryptoNative_SecCopyErrorMessageString(osStatus))
            {
                if (cfString.IsInvalid)
                {
                    return new SslException(osStatus, null);
                }

                string msg = CoreFoundation.CFStringToString(cfString);
                return new SslException(osStatus, msg);
            }
        }
    }
}
