// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Internal.NativeCrypto;

namespace Internal.Cryptography
{
    internal sealed class AesCngCryptoEncryptor : AesCngCryptoTransform
    {
        public AesCngCryptoEncryptor(CipherMode cipherMode, PaddingMode paddingMode, byte[] key, byte[] iv, int blockSize)
            : base(cipherMode, paddingMode, key, iv, blockSize)
        {
        }

        protected sealed override int UncheckedTransformBlock(SafeKeyHandle hKey, byte[] currentIv, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            int numBytesWritten = hKey.BCryptEncrypt(inputBuffer, inputOffset, inputCount, currentIv, outputBuffer, outputOffset, outputBuffer.Length);
            return numBytesWritten;
        }

        protected sealed override byte[] UncheckedTransformFinalBlock(SafeKeyHandle hKey, byte[] currentIv, byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] paddedBlock = PadBlock(inputBuffer, inputOffset, inputCount);
            byte[] output = new byte[paddedBlock.Length];
            hKey.BCryptEncrypt(paddedBlock, 0, paddedBlock.Length, currentIv, output, 0, output.Length);
            return output;
        }
    }

    internal sealed class AesCngAuthenticatedEncryptor : AesCngAuthenticatedTransform, IAuthenticatedEncryptionTransform
    {
        private byte[] _lastTag;

        public AesCngAuthenticatedEncryptor(
            CipherMode cipherMode,
            byte[] key,
            byte[] iv,
            int blockSize,
            byte[] authenticatedData,
            int authTagSize)
            : base(cipherMode, key, iv, blockSize, authenticatedData, authTagSize)
        {
        }

        protected override int UncheckedTransformBlock(
            SafeKeyHandle hKey,
            byte[] currentIv,
            byte[] inputBuffer,
            int inputOffset,
            int inputCount,
            byte[] outputBuffer,
            int outputOffset)
        {
            _lastTag = null;

            int numBytesWritten = hKey.BCryptEncrypt(inputBuffer, inputOffset, inputCount, ref _modeInfo, _chainData, outputBuffer, outputOffset, outputBuffer.Length);
            return numBytesWritten;
        }

        protected override sealed byte[] UncheckedTransformFinalBlock(
           SafeKeyHandle hKey,
           byte[] currentIv,
           byte[] inputBuffer,
           int inputOffset,
           int inputCount)
        {
            // Remove the chaining call flag, but retain the rest.
            _modeInfo.dwFlags &= ~Cng.AuthenticatedCipherModeInfoFlags.ChainCalls;

            // None of the authenticated modes require padding
            int outputSize = inputCount;
            byte[] output = GetOutputBuffer(outputSize);

            Console.WriteLine("InputCount: {0}, inputBuffer.Length: {1}", inputCount, inputBuffer.Length);

            outputSize = hKey.BCryptEncrypt(inputBuffer, inputOffset, inputCount, ref _modeInfo, _chainData, output, 0, output.Length);

            // Save the tag before we call Reset();
            _lastTag = new byte[_modeInfo.cbTag];
            Marshal.Copy(_modeInfo.pbTag, _lastTag, 0, _lastTag.Length);

            if (outputSize == 0)
            {
                return Array.Empty<byte>();
            }

            Array.Resize(ref output, outputSize);
            return output;
        }

        public byte[] GetAuthenticationTag()
        {
            if (_lastTag == null)
            {
                throw new CryptographicException();
            }

            return _lastTag.CloneByteArray();
        }
    }
}
