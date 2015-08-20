// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal
    {
        public static ICertificatePal FromHandle(IntPtr handle)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(SR.Arg_InvalidHandle, "handle");

            return new OpenSslX509CertificateReader(Interop.libcrypto.X509_dup(handle));
        }

        public static ICertificatePal FromBlob(byte[] rawData, string password, X509KeyStorageFlags keyStorageFlags)
        {
            ICertificatePal cert;

            if (TryReadX509Der(rawData, out cert) ||
                TryReadX509Pem(rawData, out cert) ||
                PkcsFormatReader.TryReadPkcs7Der(rawData, out cert) ||
                PkcsFormatReader.TryReadPkcs7Pem(rawData, out cert) ||
                PkcsFormatReader.TryReadPkcs12(rawData, password, out cert))
            {
                if (cert == null)
                {
                    // Empty collection, most likely.
                    throw new CryptographicException();
                }

                return cert;
            }

            // Unsupported
            throw Interop.libcrypto.CreateOpenSslCryptographicException();
        }

        internal static unsafe bool TryReadX509Der(byte[] rawData, out ICertificatePal certPal)
        {
            SafeX509Handle certHandle = Interop.libcrypto.OpenSslD2I(
                (ptr, b, i) => Interop.libcrypto.d2i_X509(ptr, b, i),
                rawData,
                checkHandle: false);

            if (certHandle.IsInvalid)
            {
                certPal = null;
                return false;
            }

            certPal = new OpenSslX509CertificateReader(certHandle);
            return true;
        }
        
        internal static bool TryReadX509Pem(byte[] rawData, out ICertificatePal certPal)
        {
            SafeX509Handle certHandle;
            using (SafeBioHandle bio = Interop.libcrypto.BIO_new(Interop.libcrypto.BIO_s_mem()))
            {
                Interop.libcrypto.CheckValidOpenSslHandle(bio);

                Interop.libcrypto.BIO_write(bio, rawData, rawData.Length);
                certHandle = Interop.libcrypto.PEM_read_bio_X509_AUX(bio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }

            if (certHandle.IsInvalid)
            {
                certPal = null;
                return false;
            }

            certPal = new OpenSslX509CertificateReader(certHandle);
            return true;
        }

        public static ICertificatePal FromFile(string fileName, string password, X509KeyStorageFlags keyStorageFlags)
        {
            // If we can't open the file, fail right away.
            using (SafeBioHandle fileBio = Interop.libcrypto.BIO_new_file(fileName, "rb"))
            {
                Interop.libcrypto.CheckValidOpenSslHandle(fileBio);

                return OpenSslX509CertificateReader.FromBio(fileBio, password);
            }
        }
    }
}
