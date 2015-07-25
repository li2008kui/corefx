// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed class OpenSslPkcs12Reader : IDisposable
    {
        private readonly SafePkcs12Handle _handle;
        private string _password;
        private int _pkcs7Count;
        private int _pkcs7Position = -1;

        private OpenSslPkcs12Reader(SafePkcs12Handle handle)
        {
            _handle = handle;
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

        public void Dispose()
        {
            if (_handle != null)
            {
                _handle.Dispose();
            }
        }

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
                    else
                    {
                        _password = "";
                    }
                }

                // _password is already null, don't need to assign it.
            }
            else
            {
                if (!Interop.libcrypto.PKCS12_verify_mac(_handle, password, password.Length))
                {
                    throw Interop.libcrypto.CreateOpenSslCryptographicException();
                }
                else
                {
                    _password = password;
                }
            }

            _pkcs7Count = Interop.NativeCrypto.GetPkcs7StackFieldCount(_handle);
        }

        public bool ReadNext(out SafeX509Handle x509, out SafeEvpPkeyHandle key)
        {

        }
    }
}