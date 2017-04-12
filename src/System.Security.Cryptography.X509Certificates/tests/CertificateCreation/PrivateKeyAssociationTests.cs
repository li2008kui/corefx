// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class PrivateKeyAssociationTests
    {
        public const int PROV_RSA_FULL = 1;
        public const int PROV_RSA_SCHANNEL = 12;
        public const int PROV_RSA_AES = 24;

        [Theory]
        [PlatformSpecific(TestPlatforms.Windows)]
        [InlineData(PROV_RSA_FULL, KeyNumber.Signature)]
        [InlineData(PROV_RSA_FULL, KeyNumber.Exchange)]
        // No PROV_RSA_SIG, creation does not succeed with that prov type, MSDN says it is not supported.
        [InlineData(PROV_RSA_SCHANNEL, KeyNumber.Exchange)]
        [InlineData(PROV_RSA_AES, KeyNumber.Signature)]
        [InlineData(PROV_RSA_AES, KeyNumber.Exchange)]
        public static void AssociatePersistedKey_CAPI_RSA(int provType, KeyNumber keyNumber)
        {
            CspParameters cspParameters = new CspParameters(provType)
            {
                KeyNumber = (int)keyNumber,
                KeyContainerName = nameof(AssociatePersistedKey_CAPI_RSA),
                Flags = CspProviderFlags.UseNonExportableKey,
            };

            using (RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(cspParameters))
            {
                rsaCsp.PersistKeyInCsp = false;

                // Use SHA-1 because the FULL and SCHANNEL providers can't handle SHA-2.
                HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA1;
                byte[] signature;

                CertificateRequest request = new CertificateRequest(
                    $"CN={nameof(AssociatePersistedKey_CAPI_RSA)}-{provType}-{keyNumber}",
                    rsaCsp,
                    hashAlgorithm);

                using (X509Certificate2 cert = request.SelfSign(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1)))
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    signature = rsa.SignData(Array.Empty<byte>(), hashAlgorithm, RSASignaturePadding.Pkcs1);

                    Assert.True(
                        rsaCsp.VerifyData(Array.Empty<byte>(), signature, hashAlgorithm, RSASignaturePadding.Pkcs1));
                }

                // Some certs have disposed, did they delete the key?
                cspParameters.Flags = CspProviderFlags.UseExistingKey;

                using (RSACryptoServiceProvider stillPersistedKey = new RSACryptoServiceProvider(cspParameters))
                {
                    byte[] signature2 = stillPersistedKey.SignData(
                        Array.Empty<byte>(),
                        hashAlgorithm,
                        RSASignaturePadding.Pkcs1);

                    Assert.Equal(signature, signature2);
                }
            }
        }

        [Theory]
        [PlatformSpecific(TestPlatforms.Windows)]
        [InlineData(PROV_RSA_FULL, KeyNumber.Signature)]
        [InlineData(PROV_RSA_FULL, KeyNumber.Exchange)]
        // No PROV_RSA_SIG, creation does not succeed with that prov type, MSDN says it is not supported.
        [InlineData(PROV_RSA_SCHANNEL, KeyNumber.Exchange)]
        [InlineData(PROV_RSA_AES, KeyNumber.Signature)]
        [InlineData(PROV_RSA_AES, KeyNumber.Exchange)]
        public static void AssociatePersistedKey_CAPIviaCNG_RSA(int provType, KeyNumber keyNumber)
        {
            CspParameters cspParameters = new CspParameters(provType)
            {
                KeyNumber = (int)keyNumber,
                KeyContainerName = nameof(AssociatePersistedKey_CAPIviaCNG_RSA),
                Flags = CspProviderFlags.UseNonExportableKey,
            };

            using (RSACryptoServiceProvider rsaCsp = new RSACryptoServiceProvider(cspParameters))
            {
                rsaCsp.PersistKeyInCsp = false;

                // Use SHA-1 because the FULL and SCHANNEL providers can't handle SHA-2.
                HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA1;
                byte[] signature;

                CertificateRequest request = new CertificateRequest(
                    $"CN={nameof(AssociatePersistedKey_CAPIviaCNG_RSA)}-{provType}-{keyNumber}",
                    rsaCsp,
                    hashAlgorithm);

                using (X509Certificate2 cert = request.SelfSign(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1)))
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    // `rsa` will be an RSACng wrapping the CAPI key, which means it does not expose the
                    // KeyNumber from CAPI.
                    Assert.IsAssignableFrom<RSACng>(rsa);

                    request = new CertificateRequest(
                        $"CN={nameof(AssociatePersistedKey_CAPI_RSA)}-{provType}-{keyNumber}-again",
                        rsa,
                        hashAlgorithm);

                    using (X509Certificate2 cert2 = request.SelfSign(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1)))
                    using (RSA rsa2 = cert2.GetRSAPrivateKey())
                    {
                        signature = rsa2.SignData(
                            Array.Empty<byte>(),
                            hashAlgorithm,
                            RSASignaturePadding.Pkcs1);

                        Assert.True(
                            rsaCsp.VerifyData(
                                Array.Empty<byte>(),
                                signature,
                                hashAlgorithm,
                                RSASignaturePadding.Pkcs1));
                    }
                }

                // Some certs have disposed, did they delete the key?
                cspParameters.Flags = CspProviderFlags.UseExistingKey;

                using (RSACryptoServiceProvider stillPersistedKey = new RSACryptoServiceProvider(cspParameters))
                {
                    byte[] signature2 = stillPersistedKey.SignData(
                        Array.Empty<byte>(),
                        hashAlgorithm,
                        RSASignaturePadding.Pkcs1);

                    Assert.Equal(signature, signature2);
                }
            }
        }

        [Fact]
        [PlatformSpecific(TestPlatforms.Windows)]
        public static void AssociatePersistedKey_CNG_RSA()
        {
            const string KeyName = nameof(AssociatePersistedKey_CNG_RSA);

            CngKey cngKey = null;
            HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA256;
            byte[] signature;

            try
            {
                CngKeyCreationParameters creationParameters = new CngKeyCreationParameters()
                {
                    ExportPolicy = CngExportPolicies.None,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                };

                cngKey = CngKey.Create(CngAlgorithm.Rsa, KeyName, creationParameters);

                using (RSACng rsaCng = new RSACng(cngKey))
                {
                    CertificateRequest request = new CertificateRequest(
                        $"CN={KeyName}",
                        rsaCng,
                        HashAlgorithmName.SHA256);

                    using (X509Certificate2 cert = request.SelfSign(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1)))
                    using (RSA rsa = cert.GetRSAPrivateKey())
                    {
                        signature = rsa.SignData(Array.Empty<byte>(), hashAlgorithm, RSASignaturePadding.Pkcs1);

                        Assert.True(
                            rsaCng.VerifyData(Array.Empty<byte>(), signature, hashAlgorithm, RSASignaturePadding.Pkcs1));
                    }
                }

                // Some certs have disposed, did they delete the key?
                using (CngKey stillPersistedKey = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                using (RSACng rsaCng = new RSACng(stillPersistedKey))
                {
                    byte[] signature2 = rsaCng.SignData(Array.Empty<byte>(), hashAlgorithm, RSASignaturePadding.Pkcs1);

                    Assert.Equal(signature, signature2);
                }
            }
            finally
            {
                cngKey?.Delete();
            }
        }

        [Fact]
        public static void ThirdPartyProvider_RSA()
        {
            using (RSA rsaOther = new RSAOther())
            {
                CertificateRequest request = new CertificateRequest(
                    $"CN={nameof(ThirdPartyProvider_RSA)}",
                    rsaOther,
                    HashAlgorithmName.SHA256);

                byte[] signature;
                byte[] data = request.Subject.RawData;

                using (X509Certificate2 cert = request.SelfSign(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(1)))
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    signature = rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }

                Assert.True(rsaOther.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }
    }
}