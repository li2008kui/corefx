// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainItemCopyKeychain(
            System.IntPtr item,
            out SafeKeychainHandle keychain);
        
        [DllImport(Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SecKeychainCreate")]
        private static extern int AppleCryptoNative_SecKeychainCreateTemporary(
            string path,
            int utf8PassphraseLength,
            byte[] utf8Passphrase,
            out SafeTemporaryKeychainHandle keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainDelete(SafeCreateHandle keychain);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeychainDelete(System.IntPtr keychain);

        internal static SafeKeychainHandle SecKeychainItemCopyKeychain(SafeKeychainItemHandle item)
        {
            var handle = SecKeychainItemCopyKeychain(item.DangerousGetHandle());
            System.GC.KeepAlive(item);
            return handle;
        }

        internal static SafeKeychainHandle SecKeychainItemCopyKeychain(System.IntPtr item)
        {
            SafeKeychainHandle keychain;
            int osStatus = AppleCryptoNative_SecKeychainItemCopyKeychain(item, out keychain);

            if (osStatus == 0)
            {
                return keychain;
            }

            keychain.Dispose();

            const int errSecNoSuchKeychain = -25294;
            const int errSecInvalidItemRef = -25304;

            if (osStatus == errSecNoSuchKeychain || osStatus == errSecInvalidItemRef)
            {
                return null;
            }

            throw CreateExceptionForOSStatus(osStatus);
        }

        internal static SafeTemporaryKeychainHandle SecKeychainCreateTemporary(string path, string passphrase)
        {
            byte[] utf8Passphrase = System.Text.Encoding.UTF8.GetBytes(passphrase);

            SafeTemporaryKeychainHandle keychain;

            int osStatus = AppleCryptoNative_SecKeychainCreateTemporary(
                path,
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

        internal static void SecKeychainDelete(System.IntPtr handle, bool throwOnError=true)
        {
            int osStatus = AppleCryptoNative_SecKeychainDelete(handle);

            if (throwOnError && osStatus != 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }
        }

        internal static void SecKeychainDelete(SafeCreateHandle handle)
        {
            int osStatus = AppleCryptoNative_SecKeychainDelete(handle);

            if (osStatus != 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }
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
                if (keychain == null)
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
                if (keychain == null)
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
