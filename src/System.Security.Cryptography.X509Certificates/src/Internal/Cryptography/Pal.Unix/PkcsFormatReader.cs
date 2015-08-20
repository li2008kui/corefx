// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal static class PkcsFormatReader
    {
        internal static bool TryReadPkcs7Der(byte[] rawData, out ICertificatePal certPal)
        {
            List<ICertificatePal> ignored;

            return TryReadPkcs7Der(rawData, true, out certPal, out ignored);
        }

        internal static bool TryReadPkcs7Der(byte[] rawData, out List<ICertificatePal> certPals)
        {
            ICertificatePal ignored;

            return TryReadPkcs7Der(rawData, false, out ignored, out certPals);
        }

        private static unsafe bool TryReadPkcs7Der(
            byte[] rawData,
            bool single,
            out ICertificatePal certPal,
            out List<ICertificatePal> certPals)
        {
            SafePkcs7Handle pkcs7 = Interop.libcrypto.OpenSslD2I(
                (ptr, b, i) => Interop.libcrypto.d2i_PKCS7(ptr, b, i),
                rawData,
                checkHandle: false);

            if (pkcs7.IsInvalid)
            {
                certPal = null;
                certPals = null;
                return false;
            }

            using (pkcs7)
            {
                return TryReadPkcs7(pkcs7, single, out certPal, out certPals);
            }
        }
        
        internal static bool TryReadPkcs7Pem(byte[] rawData, out ICertificatePal certPal)
        {
            List<ICertificatePal> ignored;

            return TryReadPkcs7Pem(rawData, true, out certPal, out ignored);
        }

        internal static bool TryReadPkcs7Pem(byte[] rawData, out List<ICertificatePal> certPals)
        {
            ICertificatePal ignored;

            return TryReadPkcs7Pem(rawData, false, out ignored, out certPals);
        }

        private static bool TryReadPkcs7Pem(
            byte[] rawData,
            bool single,
            out ICertificatePal certPal,
            out List<ICertificatePal> certPals)
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
                    certPals = null;
                    return false;
                }

                using (pkcs7)
                {
                    return TryReadPkcs7(pkcs7, single, out certPal, out certPals);
                }
            }
        }

        private static bool TryReadPkcs7(
            SafePkcs7Handle pkcs7,
            bool single,
            out ICertificatePal certPal,
            out List<ICertificatePal> certPals)
        {
            List<ICertificatePal> readPals = single ? null : new List<ICertificatePal>();

            using (SafeSharedX509StackHandle certs = Interop.Crypto.GetPkcs7Certificates(pkcs7))
            {
                int count = Interop.Crypto.GetX509StackFieldCount(certs);

                if (single)
                {
                    // In single cert mode read certs[0] and ignore the rest.
                    // If there isn't a certs[0] the caller will throw on our out(null)+return(true) combination.
                    if (count > 0)
                    {
                        // Use FromHandle to duplicate the handle since it would otherwise be freed when the PKCS7
                        // is Disposed.
                        certPal = CertificatePal.FromHandle(Interop.Crypto.GetX509StackField(certs, 0));
                        certPals = null;
                        return true;
                    }
                }
                else
                {
                    for (int i = 0; i < count; i++)
                    {
                        // Use FromHandle to duplicate the handle since it would otherwise be freed when the PKCS7
                        // is Disposed.
                        IntPtr certHandle = Interop.Crypto.GetX509StackField(certs, i);
                        ICertificatePal pal = CertificatePal.FromHandle(certHandle);
                        readPals.Add(pal);
                    }
                }
            }

            certPal = null;
            certPals = readPals;
            return true;
        }

        internal static bool TryReadPkcs12(byte[] rawData, string password, out ICertificatePal certPal)
        {
            List<ICertificatePal> ignored;

            return TryReadPkcs12(rawData, password, true, out certPal, out ignored);
        }

        internal static bool TryReadPkcs12(byte[] rawData, string password, out List<ICertificatePal> certPals)
        {
            ICertificatePal ignored;

            return TryReadPkcs12(rawData, password, false, out ignored, out certPals);
        }

        private static bool TryReadPkcs12(
            byte[] rawData,
            string password,
            bool single,
            out ICertificatePal readPal,
            out List<ICertificatePal> readCerts)
        {
            // DER-PKCS12
            OpenSslPkcs12Reader pfx;

            if (!OpenSslPkcs12Reader.TryRead(rawData, out pfx))
            {
                readPal = null;
                readCerts = null;
                return false;
            }

            using (pfx)
            {
                pfx.Decrypt(password);

                ICertificatePal first = null;
                List<ICertificatePal> certs = null;

                if (!single)
                {
                    certs = new List<ICertificatePal>();
                }

                foreach (OpenSslX509CertificateReader certPal in pfx.ReadCertificates())
                {
                    if (single)
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
                    else
                    {
                        certs.Add(certPal);
                    }
                }

                readPal = first;
                readCerts = certs;
                return true;
            }
        }
    }
}
