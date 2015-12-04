// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Encryption.Aes.Tests
{
    public partial class AesCipherTests
    {
        private static readonly Encoding s_asciiEncoding = new ASCIIEncoding();
        private static readonly byte[] s_helloBytes = s_asciiEncoding.GetBytes("Hello");

        // This is the expected output of many decryptions. Changing this value requires re-generating test input.
        private static readonly byte[] s_multiBlockBytes =
            s_asciiEncoding.GetBytes("This is a sentence that is longer than a block, it ensures that multi-block functions work.");

        // A randomly generated 256-bit key.
        private static readonly byte[] s_aes256Key = new byte[]
        {
            0x3E, 0x8A, 0xB2, 0x5B, 0x41, 0xF2, 0x5D, 0xEF,
            0x48, 0x4E, 0x0C, 0x50, 0xBB, 0xCF, 0x89, 0xA1,
            0x1B, 0x6A, 0x26, 0x86, 0x60, 0x36, 0x7C, 0xFD,
            0x04, 0x3D, 0xE3, 0x97, 0x6D, 0xB0, 0x86, 0x60,
        };

        // A randomly generated IV, for use in the AES-256CBC tests (and other cases' negative tests)
        private static readonly byte[] s_aes256CbcIv = new byte[]
        {
            0x43, 0x20, 0xC3, 0xE1, 0xCA, 0x80, 0x0C, 0xD1,
            0xDB, 0x74, 0xF7, 0x30, 0x6D, 0xED, 0x40, 0xF7,
        };

        // A randomly generated 192-bit key.
        private static readonly byte[] s_aes192Key = new byte[]
        {
            0xA6, 0x1E, 0xC7, 0x54, 0x37, 0x4D, 0x8C, 0xA5,
            0xA4, 0xBB, 0x99, 0x50, 0x35, 0x4B, 0x30, 0x4D,
            0x6C, 0xFE, 0x3B, 0x59, 0x65, 0xCB, 0x93, 0xE3,
        };

        // A randomly generated 128-bit key.
        private static readonly byte[] s_aes128Key = new byte[]
        {
            0x8B, 0x74, 0xCF, 0x71, 0x34, 0x99, 0x97, 0x68,
            0x22, 0x86, 0xE7, 0x52, 0xED, 0xFC, 0x56, 0x7E,
        };

        private const string CaseSourceNist = "NIST";

        public static IEnumerable<object[]> GetNistGcmTestCases()
        {
            foreach (AuthModeReferenceTest test in s_nistGcmTestCases)
            {
                yield return new object[] { test };
            }
        }

        private static readonly AuthModeReferenceTest[] s_nistGcmTestCases =
        {
            // http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
            // Appendix B, AES Test Vectors

            new AuthModeReferenceTest
            {
                Source = CaseSourceNist,
                CaseId = 1,

                Key = "00000000000000000000000000000000".HexToByteArray(),
                IV = "000000000000000000000000".HexToByteArray(),
                AuthTag = "58e2fccefa7e3061367f1d57a4e7455a".HexToByteArray(),
            },

            new AuthModeReferenceTest
            {
                Source = CaseSourceNist,
                CaseId = 2,

                Key = "00000000000000000000000000000000".HexToByteArray(),
                PlainText = "00000000000000000000000000000000".HexToByteArray(),
                IV = "000000000000000000000000".HexToByteArray(),
                CipherText = "0388dace60b6a392f328c2b971b2fe78".HexToByteArray(),
                AuthTag = "ab6e47d42cec13bdf53a67b21257bddf".HexToByteArray(),
            },

            new AuthModeReferenceTest
            {
                Source = CaseSourceNist,
                CaseId = 3,

                Key = "feffe9928665731c6d6a8f9467308308".HexToByteArray(),

                PlainText = (
                    "d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b391aafd255").HexToByteArray(),

                IV = "cafebabefacedbaddecaf888".HexToByteArray(),

                CipherText = (
                    "42831ec2217774244b7221b784d0d49c" +
                    "e3aa212f2c02a4e035c17e2329aca12e" +
                    "21d514b25466931c7d8f6a5aac84aa05" +
                    "1ba30b396a0aac973d58e091473f5985").HexToByteArray(),

                AuthTag = "4d5c2af327cd64a62cf35abd2ba6fab4".HexToByteArray(),
            },

            new AuthModeReferenceTest
            {
                Source = CaseSourceNist,
                CaseId = 4,

                Key = "feffe9928665731c6d6a8f9467308308".HexToByteArray(),

                PlainText = (
                    "d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39").HexToByteArray(),

                AuthData = "feedfacedeadbeeffeedfacedeadbeefabaddad2".HexToByteArray(),

                IV = "cafebabefacedbaddecaf888".HexToByteArray(),

                CipherText = (
                    "42831ec2217774244b7221b784d0d49c" +
                    "e3aa212f2c02a4e035c17e2329aca12e" +
                    "21d514b25466931c7d8f6a5aac84aa05" +
                    "1ba30b396a0aac973d58e091").HexToByteArray(),

                AuthTag = "5bc94fbc3221a5db94fae95ae7121a47".HexToByteArray(),
            },

            new AuthModeReferenceTest
            {
                Source = CaseSourceNist,
                CaseId = 5,

                Key = "feffe9928665731c6d6a8f9467308308".HexToByteArray(),

                PlainText = (
                    "d9313225f88406e5a55909c5aff5269a" +
                    "86a7a9531534f7da2e4c303d8a318a72" +
                    "1c3c0c95956809532fcf0e2449a6b525" +
                    "b16aedf5aa0de657ba637b39").HexToByteArray(),

                AuthData = "feedfacedeadbeeffeedfacedeadbeefabaddad2".HexToByteArray(),

                IV = "cafebabefacedbad".HexToByteArray(),

                CipherText = (
                    "61353b4c2806934a777ff51fa22a4755" +
                    "699b2a714fcdc6f83766e5f97b6c7423" +
                    "73806900e49f24b22b097544d4896b42" +
                    "4989b5e1ebac0f07c23f4598").HexToByteArray(),

                AuthTag = "3612d2e79e3b0785561be14aaca2fccb".HexToByteArray(),
            },
        };

        public class AuthModeReferenceTest
        {
            // Helps to name the test case in the logs
            public string Source;
            public int CaseId;

            // Public set / private get to make construction easy
            // and the test cases print prettily.
            public byte[] Key { set; private get; }
            public byte[] PlainText { set; private get; }
            public byte[] AuthData { set; private get; }
            public byte[] IV { set; private get; }
            public byte[] CipherText { set; private get; }
            public byte[] AuthTag { set; private get; }

            public byte[] GetKey()
            {
                return Key;
            }

            public byte[] GetPlainText()
            {
                return PlainText ?? Array.Empty<byte>();
            }

            public byte[] GetAuthData()
            {
                return AuthData;
            }

            public byte[] GetIV()
            {
                return IV;
            }

            public byte[] GetCipherText()
            {
                return CipherText ?? Array.Empty<byte>();
            }

            public byte[] GetAuthTag()
            {
                return AuthTag;
            }
        }
    }
}
