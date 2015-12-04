// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal sealed partial class AesImplementation : Aes
    {
        public sealed override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (IsAuthenticatedMode)
            {
                throw new CryptographicException();
            }

            return CreateTransform(rgbKey, rgbIV, null, null, -1, encrypting: false);
        }

        public sealed override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (IsAuthenticatedMode)
            {
                throw new CryptographicException();
            }

            return CreateTransform(rgbKey, rgbIV, null, null, -1, encrypting: true);
        }

        public override ICryptoTransform CreateAuthenticatedDecryptor(byte[] key, byte[] IV, byte[] authenticatedData, byte[] authTag)
        {
            Console.WriteLine("CreateAuthenticatedDecryptor");

            if (!IsAuthenticatedMode)
            {
                throw new CryptographicException();
            }

            return CreateTransform(key, IV, authenticatedData, authTag, -1, false);
        }

        public override IAuthenticatedEncryptionTransform CreateAuthenticatedEncryptor(
            byte[] key,
            byte[] IV,
            byte[] authenticatedData,
            int tagSizeBits)
        {
            if (!IsAuthenticatedMode)
            {
                throw new CryptographicException();
            }

            return (IAuthenticatedEncryptionTransform)CreateTransform(key, IV, authenticatedData, null, tagSizeBits, true);
        }

        public sealed override void GenerateIV()
        {
            byte[] iv = new byte[BlockSize / BitsPerByte];
            s_rng.GetBytes(iv);
            IV = iv;
        }

        public sealed override void GenerateKey()
        {
            byte[] key = new byte[KeySize / BitsPerByte];
            s_rng.GetBytes(key);
            Key = key;
        }

        protected sealed override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        private ICryptoTransform CreateTransform(
            byte[] rgbKey,
            byte[] rgbIV,
            byte[] authData,
            byte[] authTag,
            int tagSizeBits,
            bool encrypting)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("key");

            long keySize = rgbKey.Length * (long)BitsPerByte;
            if (keySize > int.MaxValue || !((int)keySize).IsLegalSize(this.LegalKeySizes))
                throw new ArgumentException(SR.Cryptography_InvalidKeySize, "key");

            if (rgbIV != null && !IsAuthenticatedMode)
            {
                long ivSize = rgbIV.Length * (long)BitsPerByte;
                if (ivSize != BlockSize)
                    throw new ArgumentException(SR.Cryptography_InvalidIVSize, "iv");
            }

            int tagSizeBytes = tagSizeBits / BitsPerByte;

            if (tagSizeBits != -1 && tagSizeBytes * BitsPerByte != tagSizeBits)
            {
                throw new CryptographicException();
            }

            if (encrypting)
                return CreateEncryptor(Mode, Padding, rgbKey, rgbIV, BlockSize / BitsPerByte, authData, tagSizeBits);
            else
                return CreateDecryptor(Mode, Padding, rgbKey, rgbIV, BlockSize / BitsPerByte, authData, authTag);
        }

        private const int BitsPerByte = 8;
        private static readonly RandomNumberGenerator s_rng = RandomNumberGenerator.Create();
    }
}
