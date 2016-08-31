// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    internal sealed class RNGCryptoServiceProvider : RandomNumberGenerator
    {
        public sealed override void GetBytes(byte[] data)
        {
            ValidateGetBytesArgs(data);
            if (data.Length > 0)
            {
                unsafe
                {
                    fixed (byte* pBuf = data)
                    {
                        int errorCode;
                        int ret = Interop.AppleCrypto.GetRandomBytes(pBuf, data.Length, out errorCode);

                        if (ret == 0)
                        {
                            throw Interop.AppleCrypto.CreateExceptionForCCError(
                                errorCode,
                                Interop.AppleCrypto.CCRNGStatus);
                        }

                        if (ret != 1)
                        {
                            throw new CryptographicException();
                        }
                    }
                }
            }
        }
    }
}
