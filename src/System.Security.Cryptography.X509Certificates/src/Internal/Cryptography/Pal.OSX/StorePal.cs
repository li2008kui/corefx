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

namespace Internal.Cryptography.Pal
{
    internal sealed partial class StorePal
    {
        public static IStorePal FromHandle(IntPtr storeHandle)
        {
            throw new PlatformNotSupportedException();
        }

        public static ILoaderPal FromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            X509ContentType contentType = X509Certificate2.GetCertContentType(rawData);

            SafeTemporaryKeychainHandle tmpKeychain;

            if (contentType == X509ContentType.Pkcs12)
            {
                tmpKeychain = Interop.AppleCrypto.CreateTemporaryKeychain();
            }
            else
            {
                tmpKeychain = SafeTemporaryKeychainHandle.InvalidHandle;
                password = SafePasswordHandle.InvalidHandle;
            }

            // Only dispose tmpKeychain on the exception path, otherwise it's managed by AppleCertLoader.
            try
            {
                SafeCFArrayHandle certs = Interop.AppleCrypto.X509ImportCollection(rawData, contentType, password, tmpKeychain);
                return new AppleCertLoader(certs, tmpKeychain);
            }
            catch
            {
                tmpKeychain.Dispose();
                throw;
            }
        }

        public static ILoaderPal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            byte[] fileBytes = File.ReadAllBytes(fileName);
            return FromBlob(fileBytes, password, keyStorageFlags);
        }

        public static IExportPal FromCertificate(ICertificatePal cert)
        {
            return new AppleCertificateExporter(cert);
        }

        public static IExportPal LinkFromCertificateCollection(X509Certificate2Collection certificates)
        {
            return new AppleCertificateExporter(certificates);
        }

        public static IStorePal FromSystemStore(string storeName, StoreLocation storeLocation, OpenFlags openFlags)
        {
            StringComparer ordinalIgnoreCase = StringComparer.OrdinalIgnoreCase;

            switch (storeLocation)
            {
                case StoreLocation.CurrentUser:
                    if (ordinalIgnoreCase.Equals("My", storeName))
                        return AppleKeychainStore.OpenDefaultKeychain(openFlags);
                    if (ordinalIgnoreCase.Equals("Root", storeName))
                        return AppleTrustStore.OpenStore(storeLocation, openFlags);

                    break;
                case StoreLocation.LocalMachine:
                    if (ordinalIgnoreCase.Equals("My", storeName))
                        return AppleKeychainStore.OpenSystemSharedKeychain(openFlags);
                    if (ordinalIgnoreCase.Equals("Root", storeName))
                        return AppleTrustStore.OpenStore(storeLocation, openFlags);

                    break;
            }

            if ((openFlags & OpenFlags.OpenExistingOnly) == OpenFlags.OpenExistingOnly)
                throw new CryptographicException(SR.Cryptography_X509_StoreNotFound);

            throw new PlatformNotSupportedException(
                SR.Format(
                    SR.Cryptography_X509_StoreCannotCreate,
                    storeName,
                    storeLocation));
        }

        private sealed class AppleTrustStore : IStorePal
        {
            private readonly StoreLocation _location;

            private AppleTrustStore(StoreLocation location)
            {
                _location = location;
            }

            public void Dispose()
            {
                // Nothing to do.
            }

            public void CloneTo(X509Certificate2Collection collection)
            {
                HashSet<X509Certificate2> dedupedCerts = new HashSet<X509Certificate2>();

                using (SafeCFArrayHandle certs = Interop.AppleCrypto.StoreEnumerateRoot(_location))
                {
                    ReadCollection(certs, dedupedCerts);
                }

                foreach (X509Certificate2 cert in dedupedCerts)
                {
                    collection.Add(cert);
                }
            }

            public void Add(ICertificatePal cert)
            {
                throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
            }

            public void Remove(ICertificatePal cert)
            {
                throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
            }

            public SafeHandle SafeHandle => null;

            internal static AppleTrustStore OpenStore(StoreLocation location, OpenFlags openFlags)
            {
                if ((openFlags & OpenFlags.ReadWrite) == OpenFlags.ReadWrite)
                    throw new CryptographicException(SR.Security_AccessDenied);

                return new AppleTrustStore(location);
            }
        }

        private sealed class AppleKeychainStore : IStorePal
        {
            private SafeKeychainHandle _keychainHandle;
            private readonly bool _readonly;

            private AppleKeychainStore(SafeKeychainHandle keychainHandle, OpenFlags openFlags)
            {
                Debug.Assert(keychainHandle != null && !keychainHandle.IsInvalid);

                _keychainHandle = keychainHandle;

                _readonly = (openFlags & (OpenFlags.ReadWrite | OpenFlags.MaxAllowed)) == 0;
            }

            public void Dispose()
            {
                _keychainHandle?.Dispose();
                _keychainHandle = null;
            }

            public void CloneTo(X509Certificate2Collection collection)
            {
                HashSet<X509Certificate2> dedupedCerts = new HashSet<X509Certificate2>();

                using (SafeCFArrayHandle identities = Interop.AppleCrypto.KeychainEnumerateIdentities(_keychainHandle))
                {
                    ReadCollection(identities, dedupedCerts);
                }

                using (SafeCFArrayHandle certs = Interop.AppleCrypto.KeychainEnumerateCerts(_keychainHandle))
                {
                    ReadCollection(certs, dedupedCerts);
                }

                foreach (X509Certificate2 cert in dedupedCerts)
                {
                    collection.Add(cert);
                }
            }

            public void Add(ICertificatePal cert)
            {
                if (_readonly)
                    throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);

                throw new NotImplementedException();
            }

            public void Remove(ICertificatePal cert)
            {
                if (_readonly)
                    throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);

                throw new NotImplementedException();
            }

            public SafeHandle SafeHandle => _keychainHandle;

            public static AppleKeychainStore OpenDefaultKeychain(OpenFlags openFlags)
            {
                return new AppleKeychainStore(Interop.AppleCrypto.SecKeychainCopyDefault(), openFlags);
            }

            public static AppleKeychainStore OpenSystemSharedKeychain(OpenFlags openFlags)
            {
                const string SharedSystemKeychainPath = "/Library/Keychains/System.keychain";
                return OpenKeychain(SharedSystemKeychainPath, openFlags);
            }

            private static AppleKeychainStore OpenKeychain(string keychainPath, OpenFlags openFlags)
            {
                return new AppleKeychainStore(Interop.AppleCrypto.SecKeychainOpen(keychainPath), openFlags);
            }
        }

        private static void ReadCollection(SafeCFArrayHandle matches, HashSet<X509Certificate2> collection)
        {
            if (matches.IsInvalid)
            {
                return;
            }

            long count = Interop.CoreFoundation.CFArrayGetCount(matches);

            for (int i = 0; i < count; i++)
            {
                IntPtr handle = Interop.CoreFoundation.CFArrayGetValueAtIndex(matches, i);

                SafeSecCertificateHandle certHandle;
                SafeSecIdentityHandle identityHandle;

                if (Interop.AppleCrypto.X509DemuxAndRetainHandle(handle, out certHandle, out identityHandle))
                {
                    X509Certificate2 cert;

                    if (certHandle.IsInvalid)
                    {
                        certHandle.Dispose();
                        cert = new X509Certificate2(new AppleCertificatePal(identityHandle));
                    }
                    else
                    {
                        identityHandle.Dispose();
                        cert = new X509Certificate2(new AppleCertificatePal(certHandle));
                    }

                    if (!collection.Add(cert))
                    {
                        cert.Dispose();
                    }
                }
            }
        }
    }
}
