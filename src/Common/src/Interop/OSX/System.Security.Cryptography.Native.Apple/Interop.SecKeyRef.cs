// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyImportEphemeral(
            byte[] pbKeyBlob,
            int cbKeyBlob,
            int isPrivateKey,
            out SafeSecKeyRefHandle ppKeyOut,
            out int pOSStatus);

        internal static SafeSecKeyRefHandle ImportEphemeralKey(byte[] keyBlob, bool hasPrivateKey)
        {
            Debug.Assert(keyBlob != null);

            SafeSecKeyRefHandle keyHandle;
            int osStatus;

            int ret = AppleCryptoNative_SecKeyImportEphemeral(
                keyBlob,
                keyBlob.Length,
                hasPrivateKey ? 1 : 0,
                out keyHandle,
                out osStatus);

            if (ret == 1 && !keyHandle.IsInvalid)
            {
                return keyHandle;
            }

            if (ret == 0)
            {
                throw CreateExceptionForCCError(osStatus, OSStatus);
            }

            Debug.Fail($"SecKeyImportEphemeral returned {ret}");
            throw new CryptographicException();
        }
    }
}

namespace System.Security.Cryptography.Apple
{
    internal sealed class SafeSecKeyRefHandle : SafeHandle
    {
        internal SafeSecKeyRefHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.CoreFoundation.CFRelease(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}