// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed class OpenSslPkcs12Reader : IDisposable
    {
        private readonly SafePkcs12Handle _pkcs12Handle;
        private SafeEvpPkeyHandle _evpPkeyHandle;
        private SafeX509Handle _x509Handle;
        private SafeX509StackHandle _caStackHandle;

        private OpenSslPkcs12Reader(SafePkcs12Handle pkcs12Handle)
        {
            _pkcs12Handle = pkcs12Handle;
        }

        public unsafe static OpenSslPkcs12Reader TryRead(byte[] data)
        {
            SafePkcs12Handle handle = Interop.libcrypto.OpenSslD2I(
                (ptr, b, i) => Interop.libcrypto.d2i_PKCS12(ptr, b, i),
                data,
                checkHandle: false);

            if (handle != null && !handle.IsInvalid)
            {
                return new OpenSslPkcs12Reader(handle);
            }

            return null;
        }

        public static OpenSslPkcs12Reader TryRead(SafeBioHandle fileBio)
        {
            SafePkcs12Handle p12 = Interop.libcrypto.d2i_PKCS12_bio(fileBio, IntPtr.Zero);

            if (p12 != null && !p12.IsInvalid)
            {
                return new OpenSslPkcs12Reader(p12);
            }

            return null;
        }

        public void Dispose()
        {
            if (_caStackHandle != null)
            {
                _caStackHandle.Dispose();
                _caStackHandle = null;
            }

            if (_x509Handle != null)
            {
                _x509Handle.Dispose();
                _x509Handle = null;
            }

            if (_evpPkeyHandle != null)
            {
                _evpPkeyHandle.Dispose();
                _evpPkeyHandle = null;
            }

            if (_pkcs12Handle != null)
            {
                _pkcs12Handle.Dispose();
            }
        }

        public void Decrypt(string password)
        {
            bool parsed = Interop.libcrypto.PKCS12_parse(
                _pkcs12Handle,
                password,
                out _evpPkeyHandle,
                out _x509Handle,
                out _caStackHandle);

            if (!parsed)
            {
                throw Interop.libcrypto.CreateOpenSslCryptographicException();
            }
        }

        public IEnumerable<OpenSslX509CertificateReader> ReadCertificates()
        {
            var certs = new List<OpenSslX509CertificateReader>();

            if (_caStackHandle != null && !_caStackHandle.IsInvalid)
            {
                int caCertCount = Interop.NativeCrypto.GetX509StackFieldCount(_caStackHandle);

                for (int i = 0; i < caCertCount; i++)
                {
                    IntPtr certPtr = Interop.NativeCrypto.GetX509StackField(_caStackHandle, i);

                    if (certPtr != IntPtr.Zero)
                    {
                        // The STACK_OF(X509) still needs to be cleaned up, so duplicate the handle out of it.
                        certs.Add(new OpenSslX509CertificateReader(Interop.libcrypto.X509_dup(certPtr)));
                    }
                }
            }

            if (_x509Handle != null && !_x509Handle.IsInvalid)
            {
                // The certificate and (if applicable) private key handles will be given over
                // to the OpenSslX509CertificateReader, and the fields here are thus nulled out to
                // prevent double-Dispose.
                OpenSslX509CertificateReader reader = new OpenSslX509CertificateReader(_x509Handle);
                _x509Handle = null;

                if (_evpPkeyHandle != null && !_evpPkeyHandle.IsInvalid)
                {
                    reader.SetPrivateKey(_evpPkeyHandle);
                    _evpPkeyHandle = null;
                }

                certs.Add(reader);
            }

            return certs;
        }

#if JEREMYISSUPERLAME
        public void Decrypt(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                // Try both the null password and the empty password.
                if (!Interop.libcrypto.PKCS12_verify_mac(_handle, null, 0))
                {
                    if (!Interop.libcrypto.PKCS12_verify_mac(_handle, "", 0))
                    {
                        throw Interop.libcrypto.CreateOpenSslCryptographicException();
                    }
                }
                else
                {
                    password = null;
                }
            }
            else if (!Interop.libcrypto.PKCS12_verify_mac(_handle, password, password.Length))
            {
                throw Interop.libcrypto.CreateOpenSslCryptographicException();
            }

            IntPtr authSafes = Interop.libcrypto.PKCS12_unpack_authsafes(_handle);

            // The average PFX will only have two entries (one cert, one private key),
            // and the average full-chain will have 4 (root CA, intermediate CA, end-entity cert,
            // and a private key).  So there's no real reason to deviate from the default list size.
            List<PfxEntry> pfxEntries = new List<PfxEntry>();

            try
            {
                ReadAuthSafes(pfxEntries, authSafes, password);
            }
            finally
            {
                foreach (PfxEntry pfxEntry in pfxEntries)
                {
                    pfxEntry.Dispose();
                }
            }
        }

        private static void ReadAuthSafes(List<PfxEntry> pfxEntries, IntPtr authSafes, string password)
        {
            int pkcs7Count = Interop.NativeCrypto.GetPkcs7StackFieldCount(authSafes);

            const int NID_keyBag = 150;
            const int NID_pkcs8ShroudedKeyBag = 151;
            const int NID_certBag = 152;
            const int NID_safeContentsBag = 155;

            for (int iPkcs7 = 0; iPkcs7 < pkcs7Count; iPkcs7++)
            {
                using (SafePkcs12SafebagStackHandle safebags = GetSafebags(authSafes, iPkcs7, password))
                {
                    if (safebags == null)
                    {
                        continue;
                    }

                    int safebagCount = Interop.NativeCrypto.GetPkcs12SafebagStackFieldCount(safebags);

                    for (int iBag = 0; iPkcs7 < safebagCount; iPkcs7++)
                    {
                        IntPtr safebag = Interop.NativeCrypto.GetPkcs12SafebagStackField(safebags, iBag);
                        int bagNid = Interop.NativeCrypto.GetPkcs12SafebagTypeNid(safebag);
                        SafeAsn1OctetStringHandle localKeyId = null;
                        SafeEvpPkeyHandle pkey = null;
                        SafeX509Handle cert = null;

                        switch (bagNid)
                        {
                            case NID_keyBag:
                                pkey = Interop.NativeCrypto.GetPkeyFromKeybag(safebag, out localKeyId);
                                break;
                            case NID_pkcs8ShroudedKeyBag:
                                pkey = Interop.NativeCrypto.GetPkeyFromShroudedKeybag(
                                    safebag,
                                    password,
                                    password == null ? 0 : password.Length,
                                    out localKeyId);

                                break;
                            case NID_certBag:
                                cert = Interop.NativeCrypto.
                        }

                        pfxEntries.Add(
                            new PfxEntry
                            {
                                PKeyHandle = pkey,
                                LocalKeyId = localKeyId,
                                Certificate = null,
                            });
                    }
                }
            }
        }

        private static SafePkcs12SafebagStackHandle GetSafebags(IntPtr authSafes, int iPkcs7, string password)
        {
            IntPtr pkcs7 = Interop.NativeCrypto.GetPkcs7StackField(authSafes, iPkcs7);
            int authSafeNid = Interop.NativeCrypto.GetPkcs7TypeNid(pkcs7);

            const int NID_pkcs7_data = 21;
            const int NID_pkcs7_encrypted = 26;

            switch (authSafeNid)
            {
                case NID_pkcs7_data:
                    return Interop.libcrypto.PKCS12_unpack_p7data(pkcs7);
                case NID_pkcs7_encrypted:
                    return Interop.libcrypto.PKCS12_unpack_p7encdata(
                        pkcs7,
                        password,
                        password == null ? 0 : password.Length);
            }

            return null;
        }

        private class PfxEntry : IDisposable
        {
            public SafeEvpPkeyHandle PKeyHandle { get; set; }
            public SafeAsn1OctetStringHandle LocalKeyId { get; set; }
            public SafeX509Handle Certificate { get; set; }

            public void Dispose()
            {
                if (PKeyHandle != null)
                {
                    PKeyHandle.Dispose();
                    PKeyHandle = null;
                }

                if (LocalKeyId != null)
                {
                    LocalKeyId.Dispose();
                    LocalKeyId = null;
                }

                if (Certificate != null)
                {
                    Certificate.Dispose();
                    Certificate = null;
                }
            }
        }
#endif
    }
}