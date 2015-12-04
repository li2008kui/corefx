// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    public abstract class SymmetricAlgorithm : IDisposable
    {
        protected SymmetricAlgorithm()
        {
            Mode = CipherMode.CBC;
            Padding = PaddingMode.PKCS7;
        }

        public virtual int BlockSize
        {
            get
            {
                return _blockSize;
            }

            set
            {
                bool validatedByZeroSkipSizeKeySizes;
                if (!value.IsLegalSize(this.LegalBlockSizes, out validatedByZeroSkipSizeKeySizes))
                    throw new CryptographicException(SR.Cryptography_InvalidBlockSize);

                if (_blockSize == value && !validatedByZeroSkipSizeKeySizes) // The !validatedByZeroSkipSizeKeySizes check preserves a very obscure back-compat behavior.
                    return;

                _blockSize = value;
                _iv = null;
                return;
            }
        }

        public virtual byte[] IV
        {
            get
            {
                if (_iv == null)
                    GenerateIV();
                return _iv.CloneByteArray();
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                if (value.Length != this.BlockSize / 8)
                    throw new CryptographicException(SR.Cryptography_InvalidIVSize);

                _iv = value.CloneByteArray();
            }
        }

        public virtual byte[] Key
        {
            get
            {
                if (_key == null)
                    GenerateKey();
                return _key.CloneByteArray();
            }

            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                long bitLength = value.Length * 8L;
                if (bitLength > int.MaxValue || !ValidKeySize((int)bitLength))
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);

                // must convert bytes to bits
                this.KeySize = (int)bitLength;
                _key = value.CloneByteArray();
            }
        }

        public virtual int KeySize
        {
            get
            {
                return _keySize;
            }

            set
            {
                if (!ValidKeySize(value))
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);

                _keySize = value;
                _key = null;
            }
        }

        public virtual KeySizes[] LegalBlockSizes
        {
            get
            {
                // Desktop compat: Unless derived classes set the protected field "LegalBlockSizesValue" to a non-null value, a NullReferenceException is what you get.
                // In the Win8P profile, the "LegalBlockSizesValue" field has been removed. So derived classes must override this property for the class to be any of any use.
                throw new NullReferenceException();
            }
        }

        public virtual KeySizes[] LegalKeySizes
        {
            get
            {
                // Desktop compat: Unless derived classes set the protected field "LegalKeySizesValue" to a non-null value, a NullReferenceException is what you get.
                // In the Win8P profile, the "LegalKeySizesValue" field has been removed. So derived classes must override this property for the class to be any of any use.
                throw new NullReferenceException();
            }
        }

        public virtual CipherMode Mode
        {
            get
            {
                return _cipherMode;
            }

            set
            {
                if (!(value == CipherMode.CBC || value == CipherMode.ECB))
                    throw new CryptographicException(SR.Cryptography_InvalidCipherMode);

                _cipherMode = value;
            }
        }

        public virtual PaddingMode Padding
        {
            get
            {
                return _paddingMode;
            }

            set
            {
                if (!(value == PaddingMode.None || value == PaddingMode.PKCS7 || value == PaddingMode.Zeros))
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
                _paddingMode = value;
            }
        }

        public virtual ICryptoTransform CreateDecryptor()
        {
            return CreateDecryptor(this.Key, this.IV);
        }

        public abstract ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV);

        public virtual ICryptoTransform CreateEncryptor()
        {
            return CreateEncryptor(Key, IV);
        }

        public abstract ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV);

        /// <summary>
        /// When overridden in a derived class, creates a symmetric decryptor object for an
        /// authenticated cipher mode with the specified authentication data and
        /// authentication tag. The secret key is read from the <see cref="Key"/> property, and
        /// the initialization vector (nonce) is read from the <see cref="IV"/> property.
        /// </summary>
        /// <param name="authenticatedData">The authenticated data buffer.</param>
        /// <param name="authTag">The authentication tag value which was computed at the time of encryption.</param>
        /// <returns>A symmetric decryptor object.</returns>
        /// <exception cref="CryptographicException">The current <see cref="Mode"/> is not an authenticated mode.</exception>
        /// <seealso cref="IsAuthenticatedMode"/>
        public virtual ICryptoTransform CreateAuthenticatedDecryptor(
            byte[] authenticatedData,
            byte[] authTag)
        {
            return CreateAuthenticatedDecryptor(Key, IV, authenticatedData, authTag);
        }

        /// <summary>
        /// When overridden in a derived class, creates a symmetric decryptor object for an
        /// authenticated cipher mode with the specified key, initialization vector (nonce), authentication data, and
        /// authentication tag.
        /// </summary>
        /// <param name="key">The secret key to use for the symmetric algorithm.</param>
        /// <param name="IV">The initialization vector to use for the symmetric algorithm. For authenticated modes this is also known as the nonce.</param>
        /// <param name="authenticatedData">The authenticated data buffer.</param>
        /// <param name="authTag">The authentication tag value which was computed at the time of encryption.</param>
        /// <returns>A symmetric decryptor object.</returns>
        /// <exception cref="CryptographicException">The current <see cref="Mode"/> is not an authenticated mode.</exception>
        /// <seealso cref="IsAuthenticatedMode"/>
        public abstract ICryptoTransform CreateAuthenticatedDecryptor(
            byte[] key,
            byte[] IV,
            byte[] authenticatedData,
            byte[] authTag);

        /// <summary>
        /// When overridden in a derived class, creates a symmetric encryptor object for an
        /// authenticated cipher mode with the specified authentication data and output tag size. The secret key is read from
        /// the <see cref="Key"/> property, and the initialization vector (nonce) is read from the <see cref="IV"/> property.
        /// </summary>
        /// <param name="authenticatedData">The authenticated data buffer.</param>
        /// <param name="tagSizeBits">The size, in bits, of the authentication tag to generate.</param>
        /// <returns>A symmetric encryptor object.</returns>
        /// <exception cref="CryptographicException">The current <see cref="Mode"/> is not an authenticated mode.</exception>
        /// <seealso cref="IsAuthenticatedMode"/>
        public virtual IAuthenticatedEncryptionTransform CreateAuthenticatedEncryptor(
            byte[] authenticatedData,
            int tagSizeBits)
        {
            return CreateAuthenticatedEncryptor(Key, IV, authenticatedData, tagSizeBits);
        }

        /// <summary>
        /// When overridden in a derived class, creates a symmetric encryptor object for an
        /// authenticated cipher mode with the specified key, initialization vector (nonce), authentication data, and output tag size.
        /// </summary>
        /// <param name="key">The secret key to use for the symmetric algorithm.</param>
        /// <param name="IV">The initialization vector to use for the symmetric algorithm. For authenticated modes this is also known as the nonce.</param>
        /// <param name="authenticatedData">The authenticated data buffer.</param>
        /// <param name="tagSizeBits">The size, in bits, of the authentication tag to generate.</param>
        /// <returns>A symmetric encryptor object.</returns>
        /// <exception cref="CryptographicException">The current <see cref="Mode"/> is not an authenticated mode.</exception>
        /// <seealso cref="IsAuthenticatedMode"/>
        public abstract IAuthenticatedEncryptionTransform CreateAuthenticatedEncryptor(
            byte[] key,
            byte[] IV,
            byte[] authenticatedData,
            int tagSizeBits);

        /// <summary>
        /// Indicates whether the current <see cref="Mode"/> value represents an Authenticated Encryption (AE) mode or not.
        /// </summary>
        /// <seealso cref="IsAuthenticatedCipherMode"/>
        public bool IsAuthenticatedMode
        {
            get { return IsAuthenticatedCipherMode(Mode); }
        }

        /// <summary>
        /// Indicates whether the specified <see cref="CipherMode"/> value represents an Authenticated Encryption (AE) mode or not.
        /// </summary>
        /// <param name="mode">The CipherMode value to test.</param>
        /// <returns><c>true</c> if <paramref name="mode"/> represents an Authenticated Encryption (AE) mode, <c>false</c> otherwise.</returns>
        public static bool IsAuthenticatedCipherMode(CipherMode mode)
        {
            switch (mode)
            {
                case CipherMode.GCM:
                case CipherMode.CCM:
                    return true;
            }

            return false;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_key != null)
                {
                    Array.Clear(_key, 0, _key.Length);
                    _key = null;
                }
                if (_iv != null)
                {
                    Array.Clear(_iv, 0, _iv.Length);
                    _iv = null;
                }
            }
        }

        public abstract void GenerateIV();

        public abstract void GenerateKey();

        private bool ValidKeySize(int bitLength)
        {
            KeySizes[] validSizes = this.LegalKeySizes;
            if (validSizes == null)
                return false;
            return bitLength.IsLegalSize(validSizes);
        }


        private CipherMode _cipherMode;
        private PaddingMode _paddingMode;
        private byte[] _key;
        private byte[] _iv;
        private int _blockSize;
        private int _keySize;
    }
}
