// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

using Microsoft.Win32.SafeHandles;
using Internal.NativeCrypto;

namespace Internal.Cryptography
{
    internal abstract class AesCngCryptoTransform : AesNativeCryptoTransform
    {
        protected AesCngCryptoTransform(
            CipherMode cipherMode,
            PaddingMode paddingMode,
            byte[] key,
            byte[] iv,
            int blockSize)
            : base(cipherMode, paddingMode, blockSize)
        {
            byte[] cipherIv = GetCipherIv(iv);

            if (cipherIv != null)
            {
                _iv = cipherIv.CloneByteArray();
                _currentIv = new byte[cipherIv.Length];
            }

            SafeBCryptAlgorithmHandle hAlg = GetCipherAlgorithm(cipherMode);
            _hKey = hAlg.BCryptImportKey(key);
        }

        protected sealed override int UncheckedTransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return UncheckedTransformBlock(_hKey, _currentIv, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        protected sealed override byte[] UncheckedTransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return UncheckedTransformFinalBlock(_hKey, _currentIv, inputBuffer, inputOffset, inputCount);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                SafeKeyHandle hKey = _hKey;
                _hKey = null;
                if (hKey != null)
                {
                    hKey.Dispose();
                }

                byte[] iv = _iv;
                _iv = null;
                if (iv != null)
                {
                    Array.Clear(iv, 0, iv.Length);
                }

                byte[] currentIv = _currentIv;
                _currentIv = null;
                if (currentIv != null)
                {
                    Array.Clear(currentIv, 0, currentIv.Length);
                }
            }

            base.Dispose(disposing);
        }

        protected override void Reset()
        {
            if (_iv != null)
            {
                Buffer.BlockCopy(_iv, 0, _currentIv, 0, _iv.Length);
            }
        }

        protected static SafeBCryptAlgorithmHandle GetCipherAlgorithm(CipherMode cipherMode)
        {
            // Windows 8 added support to set the CipherMode value on a key,
            // but Windows 7 requires that it be set on the algorithm before key creation.
            switch (cipherMode)
            {
                case CipherMode.CBC:
                    return s_hAlgCbc;
                case CipherMode.ECB:
                    return s_hAlgEcb;
                case CipherMode.GCM:
                    return s_hAlgGcm;
                default:
                    throw new NotSupportedException();
            }
        }

        private static SafeBCryptAlgorithmHandle OpenAesAlgorithm(string cipherMode)
        {
            SafeBCryptAlgorithmHandle hAlg = Cng.BCryptOpenAlgorithmProvider(Cng.BCRYPT_AES_ALGORITHM, null, Cng.OpenAlgorithmProviderFlags.NONE);
            hAlg.SetCipherMode(cipherMode);

            return hAlg;
        }

        protected abstract int UncheckedTransformBlock(SafeKeyHandle hKey, byte[] currentIv, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

        protected abstract byte[] UncheckedTransformFinalBlock(SafeKeyHandle hKey, byte[] currentIv, byte[] inputBuffer, int inputOffset, int inputCount);

        private SafeKeyHandle _hKey;
        private byte[] _iv;         // _iv holds a copy of the original IV for Reset(), until it is cleared by Dispose().
        private byte[] _currentIv;  // CNG mutates this with the updated IV for the next stage on each Encrypt/Decrypt call.

        private static readonly SafeBCryptAlgorithmHandle s_hAlgCbc = OpenAesAlgorithm("ChainingModeCBC");
        private static readonly SafeBCryptAlgorithmHandle s_hAlgEcb = OpenAesAlgorithm("ChainingModeECB");
        private static readonly SafeBCryptAlgorithmHandle s_hAlgGcm = OpenAesAlgorithm("ChainingModeGCM");
    }


    internal abstract class AesCngAuthenticatedTransform : AesCngCryptoTransform
    {
        private static readonly byte[] s_oneByteBuffer = new byte[1];

        private readonly byte[] _authTag;
        private readonly byte[] _iv;
        private readonly byte[] _authenticatedData;
        private readonly int _authTagSize;
        protected Cng.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO _modeInfo;
        protected MemoryStream _collectorStream;
        protected byte[] _chainData;
        private readonly bool _canChain;

        protected AesCngAuthenticatedTransform(
            CipherMode cipherMode,
            byte[] key,
            byte[] iv,
            int blockSize,
            byte[] authenticatedData,
            int authTagSize)
            : base(cipherMode, PaddingMode.None, key, iv, blockSize)
        {
            _iv = iv.CloneByteArray();
            _authenticatedData = authenticatedData == null ? null : authenticatedData.CloneByteArray();
            _authTagSize = authTagSize;
            _canChain = cipherMode == CipherMode.GCM;

            _modeInfo.cbSize = Marshal.SizeOf<Cng.BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
            _modeInfo.dwInfoVersion = 1; // BCRYPT_INIT_AUTH_MODE_INFO_VERSION
        }

        protected AesCngAuthenticatedTransform(
            CipherMode cipherMode,
            byte[] key,
            byte[] iv,
            int blockSize,
            byte[] authenticatedData,
            byte[] authTag)
            : this(cipherMode, key, iv, blockSize, authenticatedData, authTag == null ? 0 : authTag.Length)
        {
            _authTag = authTag;
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
            _collectorStream.Write(inputBuffer, inputOffset, inputCount);
            return 0;
        }

        protected byte[] GetOutputBuffer(int bufferSize)
        {
            // We need to ensure that pbOutput != NULL when calling BCryptEncrypt/BCryptDecrypt
            // to get the tag calculated properly.
            //     fixed (byte* pbBuf = buf)
            // results in pbBuf = 0 if buf is null OR empty.
            //
            // So, rather than using Array.Empty<byte>() or new byte[0] when bufferSize is 0, return
            // a shared 1-byte buffer that we'll never pay attention to.

            if (bufferSize == 0)
            {
                return s_oneByteBuffer;
            }

            return new byte[bufferSize];
        }

        protected override void Reset()
        {
            _modeInfo.dwFlags = 0;
            UpdateArray(ref _modeInfo.cbNonce, ref _modeInfo.pbNonce, _iv);
            UpdateArray(ref _modeInfo.cbAuthData, ref _modeInfo.pbAuthData, _authenticatedData);
            AllocArray(ref _modeInfo.cbMacContext, ref _modeInfo.pbMacContext, _authTagSize);

            if (_canChain)
            {
                unsafe
                {
                    BCRYPT_KEY_LENGTHS_STRUCT keyLengths;
                    int pcbResult;

                    Interop.BCrypt.NTSTATUS ntStatus = Interop.BCrypt.BCryptGetProperty(
                        GetCipherAlgorithm(CipherMode),
                        Interop.BCrypt.BCryptPropertyStrings.BCRYPT_AUTH_TAG_LENGTH,
                        &keyLengths,
                        sizeof(BCRYPT_KEY_LENGTHS_STRUCT),
                        out pcbResult,
                        0);

                    Console.WriteLine("{0} {1} {2}", keyLengths.dwMinLength, keyLengths.dwMaxLength, keyLengths.dwIncrement);

                    if (ntStatus != Interop.BCrypt.NTSTATUS.STATUS_SUCCESS)
                        throw Interop.BCrypt.CreateCryptographicException(ntStatus);

                    _chainData = new byte[keyLengths.dwMaxLength];
                }

                _modeInfo.dwFlags |= Cng.AuthenticatedCipherModeInfoFlags.ChainCalls;
            }

            if (_authTag != null)
            {
                // Decryption, it's input
                UpdateArray(ref _modeInfo.cbTag, ref _modeInfo.pbTag, _authTag);
            }
            else
            {
                // Encryption, it's output
                AllocArray(ref _modeInfo.cbTag, ref _modeInfo.pbTag, _authTagSize);
            }

            if (_collectorStream != null)
            {
                _collectorStream.Dispose();
            }

            _collectorStream = new MemoryStream();
        }

        private void AllocArray(ref int cbBuf, ref IntPtr pbBuf, int newSize)
        {
            Debug.Assert(newSize >= 0);

            //if (cbBuf == newSize)
            //{
            //    NtDll.ZeroMemory(pbBuf, (UIntPtr)newSize);
            //    return;
            //}

            if (pbBuf != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pbBuf);
            }

            cbBuf = newSize;
            pbBuf = Marshal.AllocHGlobal(newSize);
        }

        private void UpdateArray(ref int cbBuf, ref IntPtr pbBuf, byte[] buf)
        {
            int newSize = buf == null ? -1 : buf.Length;

            if (cbBuf == newSize)
            {
                Marshal.Copy(buf, 0, pbBuf, cbBuf);
                return;
            }

            if (pbBuf != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pbBuf);
            }

            if (buf == null)
            {
                cbBuf = 0;
                pbBuf = IntPtr.Zero;
                return;
            }

            cbBuf = buf.Length;
            pbBuf = Marshal.AllocHGlobal(cbBuf);
            Marshal.Copy(buf, 0, pbBuf, cbBuf);
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct BCRYPT_KEY_LENGTHS_STRUCT
        {
            internal int dwMinLength;
            internal int dwMaxLength;
            internal int dwIncrement;
        }
    }
}
