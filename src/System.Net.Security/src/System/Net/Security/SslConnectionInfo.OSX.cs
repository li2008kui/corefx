// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Authentication;

using TlsCipherSuite = Interop.AppleCrypto.TlsCipherSuite;

namespace System.Net.Security
{
    internal partial class SslConnectionInfo
    {
        public SslConnectionInfo(SafeSslHandle sslContext)
        {
            SslProtocols protocol;
            TlsCipherSuite cipherSuite;

            int osStatus = Interop.AppleCrypto.SslGetProtocolVersion(sslContext, out protocol);

            if (osStatus != 0)
                throw Interop.AppleCrypto.CreateExceptionForOSStatus(osStatus);

            osStatus = Interop.AppleCrypto.SslGetCipherSuite(sslContext, out cipherSuite);

            if (osStatus != 0)
                throw Interop.AppleCrypto.CreateExceptionForOSStatus(osStatus);

            Protocol = (int)protocol;

            MapCipherSuite(cipherSuite);
        }

        private void MapCipherSuite(TlsCipherSuite cipherSuite)
        {
            TlsMapping mapping;

            if (!s_tlsLookup.TryGetValue(cipherSuite, out mapping))
            {
                //Debug.Fail($"No mapping found for cipherSuite {cipherSuite}");
            }

            KeyExchangeAlg = (int)mapping.KeyExchangeAlgorithm;
            KeyExchKeySize = 0;
            DataCipherAlg = (int)mapping.CipherAlgorithm;
            DataKeySize = mapping.CipherAlgorithmStrength;
            DataHashAlg = (int)mapping.HashAlgorithm;
            DataHashKeySize = (int)mapping.HashAlgorithmStrength;
        }

        private struct TlsMapping
        {
            internal ExchangeAlgorithmType KeyExchangeAlgorithm;
            // The Key Exchange size isn't part of the CipherSuite
            internal CipherAlgorithmType CipherAlgorithm;
            internal int CipherAlgorithmStrength;
            internal HashAlgorithmType HashAlgorithm;
            internal int HashAlgorithmStrength;
        }

        private static readonly Dictionary<TlsCipherSuite, TlsMapping> s_tlsLookup = new Dictionary<TlsCipherSuite, TlsMapping>
        {
            {
                TlsCipherSuite.TLS_NULL_WITH_NULL_NULL,

                new TlsMapping
                {
                    KeyExchangeAlgorithm = ExchangeAlgorithmType.None,
                    CipherAlgorithm = CipherAlgorithmType.None,
                    CipherAlgorithmStrength = 0,
                    HashAlgorithm = HashAlgorithmType.None,
                    HashAlgorithmStrength = 0
                }
            },

            {
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

                new TlsMapping
                {
                    KeyExchangeAlgorithm = ExchangeAlgorithmType.RsaKeyX,
                    CipherAlgorithm = CipherAlgorithmType.Aes128,
                    CipherAlgorithmStrength = 128,
                    HashAlgorithm = HashAlgorithmType.Sha256,
                    HashAlgorithmStrength = 256,
                }
            },

            {
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

                new TlsMapping
                {
                    KeyExchangeAlgorithm = ExchangeAlgorithmType.RsaKeyX,
                    CipherAlgorithm = CipherAlgorithmType.Aes256,
                    CipherAlgorithmStrength = 256,
                    HashAlgorithm = HashAlgorithmType.Sha384,
                    HashAlgorithmStrength = 384,
                }
            },
        };
    }
}
