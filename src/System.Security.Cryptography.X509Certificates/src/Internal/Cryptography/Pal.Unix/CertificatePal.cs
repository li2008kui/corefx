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
            // If we can see a hyphen, assume it's PEM.  Otherwise try DER-X509, then fall back to DER-PKCS12.
            SafeX509Handle cert;

            // PEM
            if (rawData[0] == '-')
            {
                // PEM-X509
                cert = ReadPemX509(rawData);

                // PEM-PKCS7
                if (cert.IsInvalid)
                {
                    cert = ReadPemPkcs7(rawData);
                }

                Interop.libcrypto.CheckValidOpenSslHandle(cert);

                return new OpenSslX509CertificateReader(cert);
            }

            // DER-X509
            cert = ReadDerX509(rawData);

            if (!cert.IsInvalid)
            {
                return new OpenSslX509CertificateReader(cert);
            }

            // DER-PKCS12
            OpenSslPkcs12Reader pfx;

            if (OpenSslPkcs12Reader.TryRead(rawData, out pfx))
            {
                using (pfx)
                {
                    pfx.Decrypt(password);

                    ICertificatePal first = null;

                    foreach (OpenSslX509CertificateReader certPal in pfx.ReadCertificates())
                    {
                        // When requesting an X509Certificate2 from a PFX only the first entry is
                        // returned.  Other entries should be disposed.
                        if (first == null)
                        {
                            first = certPal;
                        }
                        else
                        {
                            certPal.Dispose();
                        }
                    }

                    if (first == null)
                    {
                        throw new CryptographicException();
                    }

                    return first;
                }
            }

            // Unsupported
            throw Interop.libcrypto.CreateOpenSslCryptographicException();
        }

        private static unsafe SafeX509Handle ReadDerX509(byte[] rawData)
        {
            return Interop.libcrypto.OpenSslD2I(
                (ptr, b, i) => Interop.libcrypto.d2i_X509(ptr, b, i),
                rawData,
                checkHandle: false);
        }

        private static SafeX509Handle ReadPemX509(byte[] rawData)
        {
            SafeX509Handle cert;
            using (SafeBioHandle bio = Interop.libcrypto.BIO_new(Interop.libcrypto.BIO_s_mem()))
            {
                Interop.libcrypto.CheckValidOpenSslHandle(bio);

                Interop.libcrypto.BIO_write(bio, rawData, rawData.Length);
                cert = Interop.libcrypto.PEM_read_bio_X509_AUX(bio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            }
            return cert;
        }

        private static SafeX509Handle ReadPemPkcs7(byte[] rawData)
        {
            using (SafeBioHandle bio = Interop.libcrypto.BIO_new(Interop.libcrypto.BIO_s_mem()))
            {
                Interop.libcrypto.CheckValidOpenSslHandle(bio);

                Interop.libcrypto.BIO_write(bio, rawData, rawData.Length);

                SafePkcs7Handle pkcs7 =
                    Interop.libcrypto.PEM_read_bio_PKCS7(bio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (pkcs7.IsInvalid)
                {
                    return SafeX509Handle.InvalidHandle;
                }

                using (pkcs7)
                using (SafeSharedX509StackHandle certs = Interop.Crypto.GetPkcs7Certificates(pkcs7))
                {
                    int count = Interop.Crypto.GetX509StackFieldCount(certs);

                    if (count > 0)
                    {
                        return Interop.libcrypto.X509_dup(Interop.Crypto.GetX509StackField(certs, 0));
                    }
                }
            }

            return SafeX509Handle.InvalidHandle;
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
