// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal static class PkcsFormatReader
    {
        internal static bool TryReadPkcs7Der(byte[] rawData, out ICertificatePal certPal)
        {
            return TryReadPkcs7Der(rawData, true, out certPal);
        }

        private static unsafe bool TryReadPkcs7Der(byte[] rawData, bool single, out ICertificatePal certPal)
        {
            SafePkcs7Handle pkcs7 = Interop.libcrypto.OpenSslD2I(
                (ptr, b, i) => Interop.libcrypto.d2i_PKCS7(ptr, b, i),
                rawData,
                checkHandle: false);

            if (pkcs7.IsInvalid)
            {
                certPal = null;
                return false;
            }

            return TryReadPkcs7(pkcs7, out certPal);
        }
        
        internal static bool TryReadPkcs7Pem(byte[] rawData, out ICertificatePal certPal)
        {
            return TryReadPkcs7Pem(rawData, true, out certPal);
        }

        private static bool TryReadPkcs7Pem(byte[] rawData, bool single, out ICertificatePal certPal)
        {
            using (SafeBioHandle bio = Interop.libcrypto.BIO_new(Interop.libcrypto.BIO_s_mem()))
            {
                Interop.libcrypto.CheckValidOpenSslHandle(bio);

                Interop.libcrypto.BIO_write(bio, rawData, rawData.Length);

                SafePkcs7Handle pkcs7 =
                    Interop.libcrypto.PEM_read_bio_PKCS7(bio, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

                if (pkcs7.IsInvalid)
                {
                    certPal = null;
                    return false;
                }

                return TryReadPkcs7(pkcs7, out certPal);
            }
        }

        private static bool TryReadPkcs7(SafePkcs7Handle pkcs7, out ICertificatePal certPal)
        {
            using (pkcs7)
            using (SafeSharedX509StackHandle certs = Interop.Crypto.GetPkcs7Certificates(pkcs7))
            {
                int count = Interop.Crypto.GetX509StackFieldCount(certs);

                if (count > 0)
                {
                    // Use FromHandle to duplicate the handle since it would otherwise be freed when the PKCS7
                    // is Disposed.
                    certPal = CertificatePal.FromHandle(Interop.Crypto.GetX509StackField(certs, 0));
                    return true;
                }

                certPal = null;
                return true;
            }
        }

        internal static bool TryReadPkcs12(byte[] rawData, string password, out ICertificatePal certPal)
        {
            return TryReadPkcs12(rawData, password, true, out certPal);
        }

        private static bool TryReadPkcs12(byte[] rawData, string password, bool single, out ICertificatePal readPal)
        {
            // DER-PKCS12
            OpenSslPkcs12Reader pfx;

            if (!OpenSslPkcs12Reader.TryRead(rawData, out pfx))
            {
                readPal = null;
                return false;
            }

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

                readPal = first;
                return true;
            }
        }
    }
}
