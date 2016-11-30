// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509ImportCertificate(
            byte[] pbKeyBlob,
            int cbKeyBlob,
            SafeCreateHandle cfPfxPassphrase,
            out SafeSecCertificateHandle pCertOut,
            out SafeCreateHandle pPrivateKeyOut,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509GetRawData(
            SafeSecCertificateHandle cert,
            out SafeCFDataHandle cfDataOut,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509GetPublicKey(SafeSecCertificateHandle cert, out SafeSecKeyRefHandle publicKey, out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_X509GetContentType")]
        internal static extern X509ContentType X509GetContentType(byte[] pbData, int cbData);

        internal static byte[] X509GetRawData(SafeSecCertificateHandle cert)
        {
            int osStatus;
            SafeCFDataHandle data;

            int ret = AppleCryptoNative_X509GetRawData(
                cert,
                out data,
                out osStatus);

            if (ret == 1)
            {
                return CoreFoundation.CFGetData(data);
            }

            if (ret == 0)
            {
                throw CreateExceptionForCCError(osStatus, OSStatus);
            }

            Debug.Fail($"Unexpected return value {ret}");
            throw new CryptographicException();
        }

        internal static SafeSecCertificateHandle X509ImportCertificate(
            byte[] bytes,
            SafePasswordHandle importPassword,
            out SafeCreateHandle privateKey)
        {
            SafeSecCertificateHandle certHandle;
            int osStatus;
            int ret;

            SafeCreateHandle cfPassphrase = s_nullExportString;
            bool releasePassword = false;

            try
            {
                if (!importPassword.IsInvalid)
                {
                    importPassword.DangerousAddRef(ref releasePassword);
                    IntPtr passwordHandle = importPassword.DangerousGetHandle();

                    if (passwordHandle != IntPtr.Zero)
                    {
                        cfPassphrase = CoreFoundation.CFStringCreateWithCString(passwordHandle);
                    }
                }

                ret = AppleCryptoNative_X509ImportCertificate(
                    bytes,
                    bytes.Length,
                    cfPassphrase,
                    out certHandle,
                    out privateKey,
                    out osStatus);
            }
            finally
            {
                if (releasePassword)
                {
                    importPassword.DangerousRelease();
                }

                if (cfPassphrase != s_nullExportString)
                {
                    cfPassphrase.Dispose();
                }
            }

            if (ret == 1)
            {
                return certHandle;
            }

            certHandle.Dispose();
            privateKey.Dispose();

            const int SeeOSStatus = 0;
            const int ImportReturnedNull = -1;
            const int ImportReturnedEmpty = -2;

            switch (ret)
            {
                case SeeOSStatus:
                    throw CreateExceptionForCCError(osStatus, OSStatus);
                case ImportReturnedNull:
                case ImportReturnedEmpty:
                    throw new CryptographicException();
                default:
                    Debug.Fail($"Unexpected return value {ret}");
                    throw new CryptographicException();
            }
        }

        internal static SafeSecKeyRefHandle X509GetPublicKey(SafeSecCertificateHandle cert)
        {
            SafeSecKeyRefHandle publicKey;
            int osStatus;
            int ret = AppleCryptoNative_X509GetPublicKey(cert, out publicKey, out osStatus);

            if (ret == 1)
            {
                return publicKey;
            }

            publicKey.Dispose();

            if (ret == 0)
            {
                throw CreateExceptionForCCError(osStatus, OSStatus);
            }

            Debug.Fail($"Unexpected return value {ret}");
            throw new CryptographicException();
        }
    }
}

namespace System.Security.Cryptography.X509Certificates
{
    internal class SafeSecCertificateHandle : SafeHandle
    {
        public SafeSecCertificateHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.CoreFoundation.CFRelease(handle);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}
