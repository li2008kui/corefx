// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
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
        private static extern int AppleCryptoNative_SecKeychainItemCopyKeychain(
            IntPtr item,
            out SafeKeychainHandle keychain);
        
        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SecKeychainCreate")]
        private static extern int AppleCryptoNative_SecKeychainCreateTemporary(
            string path,
            int utf8PassphraseLength,
            byte[] utf8Passphrase,
            out SafeTemporaryKeychainHandle keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainDelete(IntPtr keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainCopyDefault(out SafeKeychainHandle keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainOpen(
            string keychainPath,
            out SafeKeychainHandle keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainEnumerateCerts(
            SafeKeychainHandle keychain,
            out SafeCFArrayHandle matches,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainEnumerateIdentities(
            SafeKeychainHandle keychain,
            out SafeCFArrayHandle matches,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_StoreEnumerateUserRoot(
            out SafeCFArrayHandle pCertsOut,
            out int pOSStatusOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_StoreEnumerateMachineRoot(
            out SafeCFArrayHandle pCertsOut,
            out int pOSStatusOut);

        internal static SafeKeychainHandle SecKeychainItemCopyKeychain(SafeKeychainItemHandle item)
        {
            var handle = SecKeychainItemCopyKeychain(item.DangerousGetHandle());
            GC.KeepAlive(item);
            return handle;
        }

        internal static SafeKeychainHandle SecKeychainItemCopyKeychain(IntPtr item)
        {
            SafeKeychainHandle keychain;
            int osStatus = AppleCryptoNative_SecKeychainItemCopyKeychain(item, out keychain);

            // A whole lot of NULL is expected from this.
            // Any key or cert which isn't keychain-backed, and this is the primary way we'd find that out.
            if (keychain.IsInvalid)
            {
                GC.SuppressFinalize(keychain);
            }

            if (osStatus == 0)
            {
                return keychain;
            }

            throw CreateExceptionForOSStatus(osStatus);
        }

        internal static SafeKeychainHandle SecKeychainCopyDefault()
        {
            SafeKeychainHandle keychain;
            int osStatus = AppleCryptoNative_SecKeychainCopyDefault(out keychain);

            if (osStatus == 0)
            {
                return keychain;
            }

            keychain.Dispose();
            throw CreateExceptionForOSStatus(osStatus);
        }

        internal static SafeKeychainHandle SecKeychainOpen(string keychainPath)
        {
            SafeKeychainHandle keychain;
            int osStatus = AppleCryptoNative_SecKeychainOpen(keychainPath, out keychain);

            if (osStatus == 0)
            {
                return keychain;
            }

            keychain.Dispose();
            throw CreateExceptionForOSStatus(osStatus);
        }

        internal static SafeCFArrayHandle KeychainEnumerateCerts(SafeKeychainHandle keychainHandle)
        {
            SafeCFArrayHandle matches;
            int osStatus;
            int result = AppleCryptoNative_SecKeychainEnumerateCerts(keychainHandle, out matches, out osStatus);

            if (result == 1)
            {
                return matches;
            }

            matches.Dispose();

            if (result == 0)
                throw CreateExceptionForOSStatus(osStatus);

            Debug.Fail($"Unexpected result from AppleCryptoNative_SecKeychainEnumerateCerts: {result}");
            throw new CryptographicException();
        }

        internal static SafeCFArrayHandle KeychainEnumerateIdentities(SafeKeychainHandle keychainHandle)
        {
            SafeCFArrayHandle matches;
            int osStatus;
            int result = AppleCryptoNative_SecKeychainEnumerateIdentities(keychainHandle, out matches, out osStatus);

            if (result == 1)
            {
                return matches;
            }

            matches.Dispose();

            if (result == 0)
                throw CreateExceptionForOSStatus(osStatus);

            Debug.Fail($"Unexpected result from AppleCryptoNative_SecKeychainEnumerateCerts: {result}");
            throw new CryptographicException();
        }

        internal static SafeTemporaryKeychainHandle CreateTemporaryKeychain()
        {
            string tmpKeychainPath = Path.Combine(
                Path.GetTempPath(),
                Guid.NewGuid().ToString("N") + ".keychain");

            // Use a distinct GUID so that if a keychain is abandoned it isn't recoverable.
            string tmpKeychainPassphrase = Guid.NewGuid().ToString("N");

            byte[] utf8Passphrase = System.Text.Encoding.UTF8.GetBytes(tmpKeychainPassphrase);

            SafeTemporaryKeychainHandle keychain;

            int osStatus = AppleCryptoNative_SecKeychainCreateTemporary(
                tmpKeychainPath,
                utf8Passphrase.Length,
                utf8Passphrase,
                out keychain);

            SafeTemporaryKeychainHandle.TrackKeychain(keychain);

            if (osStatus != 0)
            {
                keychain.Dispose();
                throw CreateExceptionForOSStatus(osStatus);
            }

            return keychain;
        }

        internal static void SecKeychainDelete(IntPtr handle, bool throwOnError=true)
        {
            int osStatus = AppleCryptoNative_SecKeychainDelete(handle);

            if (throwOnError && osStatus != 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }
        }

        internal static SafeCFArrayHandle StoreEnumerateRoot(StoreLocation location)
        {
            int result;
            SafeCFArrayHandle matches;
            int osStatus;

            if (location == StoreLocation.CurrentUser)
            {
                result = AppleCryptoNative_StoreEnumerateUserRoot(out matches, out osStatus);
            }
            else if (location == StoreLocation.LocalMachine)
            {
                result = AppleCryptoNative_StoreEnumerateMachineRoot(out matches, out osStatus);
            }
            else
            {
                Debug.Fail($"Unrecognized StoreLocation value: {location}");
                throw new CryptographicException();
            }

            if (result == 1)
            {
                return matches;
            }

            matches.Dispose();

            if (result == 0)
                throw CreateExceptionForOSStatus(osStatus);

            Debug.Fail($"Unexpected result from AppleCryptoNative_StoreEnumerateRoot: {result}");
            throw new CryptographicException();
        }
    }
}

namespace System.Security.Cryptography.Apple
{
    internal class SafeKeychainItemHandle : SafeHandle
    {
        internal SafeKeychainItemHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            SafeTemporaryKeychainHandle.ReleaseItem(handle);
            Interop.CoreFoundation.CFRelease(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }

    internal class SafeKeychainHandle : SafeHandle
    {
        internal SafeKeychainHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        internal SafeKeychainHandle(IntPtr handle)
            : base(handle, ownsHandle: true)
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

    internal sealed class SafeTemporaryKeychainHandle : SafeKeychainHandle
    {
        private static readonly Dictionary<IntPtr, SafeTemporaryKeychainHandle> s_lookup =
            new Dictionary<IntPtr, SafeTemporaryKeychainHandle>();

        internal SafeTemporaryKeychainHandle()
        {
        }

        protected override bool ReleaseHandle()
        {
            lock (s_lookup)
            {
                s_lookup.Remove(handle);
            }

            Interop.AppleCrypto.SecKeychainDelete(handle, throwOnError: false);
            return base.ReleaseHandle();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && SafeHandleCache<SafeTemporaryKeychainHandle>.IsCachedInvalidHandle(this))
            {
                return;
            }

            base.Dispose(disposing);
        }

        public static SafeTemporaryKeychainHandle InvalidHandle =>
            SafeHandleCache<SafeTemporaryKeychainHandle>.GetInvalidHandle(() => new SafeTemporaryKeychainHandle());

        internal static void TrackKeychain(SafeTemporaryKeychainHandle toTrack)
        {
            if (toTrack.IsInvalid)
            {
                return;
            }

            lock (s_lookup)
            {
                Debug.Assert(!s_lookup.ContainsKey(toTrack.handle));

                s_lookup[toTrack.handle] = toTrack;
            }
        }

        internal static void TrackItem(SafeKeychainItemHandle keychainItem)
        {
            if (keychainItem.IsInvalid)
                return;

            using (SafeKeychainHandle keychain = Interop.AppleCrypto.SecKeychainItemCopyKeychain(keychainItem))
            {
                if (keychain.IsInvalid)
                {
                    return;
                }

                lock (s_lookup)
                {
                    SafeTemporaryKeychainHandle temporaryHandle;

                    if (s_lookup.TryGetValue(keychain.DangerousGetHandle(), out temporaryHandle))
                    {
                        bool ignored = false;
                        temporaryHandle.DangerousAddRef(ref ignored);
                    }
                }
            }
        }

        internal static void ReleaseItem(IntPtr keychainItem)
        {
            using (SafeKeychainHandle keychain = Interop.AppleCrypto.SecKeychainItemCopyKeychain(keychainItem))
            {
                if (keychain.IsInvalid)
                {
                    return;
                }

                lock (s_lookup)
                {
                    SafeTemporaryKeychainHandle temporaryHandle;

                    if (s_lookup.TryGetValue(keychain.DangerousGetHandle(), out temporaryHandle))
                    {
                        temporaryHandle.DangerousRelease();
                    }
                }
            }
        }
    }
}
