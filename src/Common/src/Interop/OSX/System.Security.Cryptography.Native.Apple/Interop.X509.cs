// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.IO;
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
            string tmpKeychainPath,
            out SafeSecCertificateHandle pCertOut,
            out SafeSecIdentityHandle pPrivateKeyOut,
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

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509CopyCertFromIdentity(
            SafeSecIdentityHandle identity,
            out SafeSecCertificateHandle cert);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509CopyPrivateKeyFromIdentity(
            SafeSecIdentityHandle identity,
            out SafeSecKeyRefHandle key);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509DemuxAndRetainHandle(
            IntPtr handle,
            out SafeSecCertificateHandle certHandle,
            out SafeSecIdentityHandle identityHandle);

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
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"Unexpected return value {ret}");
            throw new CryptographicException();
        }

        internal static SafeSecCertificateHandle X509ImportCertificate(
            byte[] bytes,
            SafePasswordHandle importPassword,
            out SafeSecIdentityHandle identityHandle)
        {
            SafeSecCertificateHandle certHandle;
            int osStatus;
            int ret;

            SafeCreateHandle cfPassphrase = s_nullExportString;
            bool releasePassword = false;

            string tmpKeychainPath = Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N") + ".keychain");

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
                    tmpKeychainPath,
                    out certHandle,
                    out identityHandle,
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

                Debug.Assert(
                    !File.Exists(tmpKeychainPath),
                    $"A temporary keychain was created at {tmpKeychainPath} and was not deleted");
            }

            if (ret == 1)
            {
                return certHandle;
            }

            certHandle.Dispose();
            identityHandle.Dispose();

            const int SeeOSStatus = 0;
            const int ImportReturnedNull = -1;
            const int ImportReturnedEmpty = -2;

            switch (ret)
            {
                case SeeOSStatus:
                    throw CreateExceptionForOSStatus(osStatus);
                case ImportReturnedNull:
                case ImportReturnedEmpty:
                    throw new CryptographicException();
                default:
                    Debug.Fail($"Unexpected return value {ret}");
                    throw new CryptographicException();
            }
        }

        internal static SafeSecCertificateHandle X509GetCertFromIdentity(SafeSecIdentityHandle identity)
        {
            SafeSecCertificateHandle cert;
            int osStatus = AppleCryptoNative_X509CopyCertFromIdentity(identity, out cert);

            if (osStatus != 0)
            {
                cert.Dispose();
                throw CreateExceptionForOSStatus(osStatus);
            }

            if (cert.IsInvalid)
            {
                cert.Dispose();
                throw new CryptographicException(SR.Arg_InvalidHandle);
            }

            return cert;
        }

        internal static SafeSecKeyRefHandle X509GetPrivateKeyFromIdentity(SafeSecIdentityHandle identity)
        {
            SafeSecKeyRefHandle key;
            int osStatus = AppleCryptoNative_X509CopyPrivateKeyFromIdentity(identity, out key);

            if (osStatus != 0)
            {
                key.Dispose();
                throw CreateExceptionForOSStatus(osStatus);
            }

            if (key.IsInvalid)
            {
                key.Dispose();
                throw new CryptographicException(SR.Arg_InvalidHandle);
            }

            return key;
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
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"Unexpected return value {ret}");
            throw new CryptographicException();
        }

        internal static bool X509DemuxAndRetainHandle(
            IntPtr handle,
            out SafeSecCertificateHandle certHandle,
            out SafeSecIdentityHandle identityHandle)
        {
            int result = AppleCryptoNative_X509DemuxAndRetainHandle(handle, out certHandle, out identityHandle);

            switch (result)
            {
                case 1:
                    return true;
                case 0:
                    return false;
                default:
                    Debug.Fail($"AppleCryptoNative_X509DemuxAndRetainHandle returned {result}");
                    throw new CryptographicException();
            }
        }
    }
}

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class SafeSecIdentityHandle : SafeHandle
    {
        public SafeSecIdentityHandle()
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

    internal sealed class SafeSecCertificateHandle : SafeHandle
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
