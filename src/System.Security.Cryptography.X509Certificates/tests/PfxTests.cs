// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests
{
    public static class PfxTests
    {
        [Fact]
        public static void TestConstructor()
        {
            byte[] expectedThumbprint = "71cb4e2b02738ad44f8b382c93bd17ba665f9914".HexToByteArray();

            using (var c = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, X509KeyStorageFlags.EphemeralKeys))
            {
                string subject = c.Subject;
                Assert.Equal("CN=MyName", subject);
                byte[] thumbPrint = c.GetCertHash();
                Assert.Equal(expectedThumbprint, thumbPrint);
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void EnsurePrivateKeyPreferred(X509KeyStorageFlags openFlags)
        {
            using (var cert = new X509Certificate2(TestData.ChainPfxBytes, TestData.ChainPfxPassword, openFlags))
            {
                // While checking cert.HasPrivateKey first is most matching of the test description, asserting
                // on the certificate's simple name will provide a more diagnosable failure.
                Assert.Equal("test.local", cert.GetNameInfo(X509NameType.SimpleName, false));
                Assert.True(cert.HasPrivateKey, "cert.HasPrivateKey");
            }
        }

        [Fact]
        public static void TestRawData()
        {
            byte[] expectedRawData = (
                "308201e530820152a0030201020210d5b5bc1c458a558845" +
                "bff51cb4dff31c300906052b0e03021d05003011310f300d" +
                "060355040313064d794e616d65301e170d31303034303130" +
                "38303030305a170d3131303430313038303030305a301131" +
                "0f300d060355040313064d794e616d6530819f300d06092a" +
                "864886f70d010101050003818d0030818902818100b11e30" +
                "ea87424a371e30227e933ce6be0e65ff1c189d0d888ec8ff" +
                "13aa7b42b68056128322b21f2b6976609b62b6bc4cf2e55f" +
                "f5ae64e9b68c78a3c2dacc916a1bc7322dd353b32898675c" +
                "fb5b298b176d978b1f12313e3d865bc53465a11cca106870" +
                "a4b5d50a2c410938240e92b64902baea23eb093d9599e9e3" +
                "72e48336730203010001a346304430420603551d01043b30" +
                "39801024859ebf125e76af3f0d7979b4ac7a96a113301131" +
                "0f300d060355040313064d794e616d658210d5b5bc1c458a" +
                "558845bff51cb4dff31c300906052b0e03021d0500038181" +
                "009bf6e2cf830ed485b86d6b9e8dffdcd65efc7ec145cb93" +
                "48923710666791fcfa3ab59d689ffd7234b7872611c5c23e" +
                "5e0714531abadb5de492d2c736e1c929e648a65cc9eb63cd" +
                "84e57b5909dd5ddf5dbbba4a6498b9ca225b6e368b94913b" +
                "fc24de6b2bd9a26b192b957304b89531e902ffc91b54b237" +
                "bb228be8afcda26476").HexToByteArray();

            using (var c = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, X509KeyStorageFlags.EphemeralKeys))
            {
                byte[] rawData = c.RawData;
                Assert.Equal(expectedRawData, rawData);
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void GetRSAPrivateKey(X509KeyStorageFlags openFlags)
        {
            using (var c = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, openFlags))
            {
                bool hasPrivateKey = c.HasPrivateKey;
                Assert.True(hasPrivateKey);

                using (RSA rsa = c.GetRSAPrivateKey())
                {
                    byte[] hash = new byte[20];
                    byte[] sig = rsa.SignHash(hash, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                    Assert.Equal(s_expectedSig, sig);
                }

                using (ECDsa ecdsa = c.GetECDsaPrivateKey())
                {
                    Assert.Null(ecdsa);
                }
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void GetRSAPrivateKey_MultipleCalls(X509KeyStorageFlags openFlags)
        {
            using (var c = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, openFlags))
            {
                Assert.True(c.HasPrivateKey);

                byte[] hash = new byte[20];

                for (int i = 0; i < 3; i++)
                {
                    using (RSA rsa = c.GetRSAPrivateKey())
                    {
                        byte[] sig = rsa.SignHash(hash, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
                        Assert.Equal(s_expectedSig, sig);
                    }

                    Assert.True(c.HasPrivateKey, $"c.HasPrivateKey after read, i={i}");
                }
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.Exportable)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys | X509KeyStorageFlags.Exportable)]
        public static void ExportWithPrivateKey(X509KeyStorageFlags openFlags)
        {
            using (var cert = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, openFlags))
            {
                const string password = "NotVerySecret";

                byte[] pkcs12 = cert.Export(X509ContentType.Pkcs12, password);

                using (var certFromPfx = new X509Certificate2(pkcs12, password, X509KeyStorageFlags.EphemeralKeys))
                {
                    Assert.True(certFromPfx.HasPrivateKey);
                    Assert.Equal(cert, certFromPfx);
                }
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void ReadECDsaPrivateKey_WindowsPfx(X509KeyStorageFlags openFlags)
        {
            using (var cert = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Pfx_Windows, "Test", openFlags))
            using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                Assert.NotNull(ecdsa);
                Assert.Null(rsa);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    AssertEccAlgorithm(ecdsa, "ECDSA_P256");
                }

                byte[] signature = ecdsa.SignData(Array.Empty<byte>(), HashAlgorithmName.SHA256);
            }
        }

        [Theory]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void ReadECDsaPrivateKey_OpenSslPfx(X509KeyStorageFlags openFlags)
        {
            using (var cert = new X509Certificate2(TestData.ECDsaP256_DigitalSignature_Pfx_OpenSsl, "Test", openFlags))
            using (ECDsa ecdsa = cert.GetECDsaPrivateKey())
            using (RSA rsa = cert.GetRSAPrivateKey())
            {
                Assert.NotNull(ecdsa);
                Assert.Null(rsa);

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    // If Windows were to start detecting this case as ECDSA that wouldn't be bad,
                    // but this assert is the only proof that this certificate was made with OpenSSL.
                    //
                    // Windows ECDSA PFX files contain metadata in the private key keybag which identify it
                    // to Windows as ECDSA.  OpenSSL doesn't have anywhere to persist that data when
                    // extracting it to the key PEM file, and so no longer has it when putting the PFX
                    // together.  But, it also wouldn't have had the Windows-specific metadata when the
                    // key was generated on the OpenSSL side in the first place.
                    //
                    // So, again, it's not important that Windows "mis-detects" this as ECDH.  What's
                    // important is that we were able to create an ECDsa object from it.
                    AssertEccAlgorithm(ecdsa, "ECDH_P256");
                }

                byte[] signature = ecdsa.SignData(Array.Empty<byte>(), HashAlgorithmName.SHA256);
            }
        }

        [Theory]
        [OuterLoop(/* The test sleeps */)]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void UseRSAKeyAfterCertDispose(X509KeyStorageFlags openFlags)
        {
            RSA rsaPrivate = null;
            RSA rsaPublic = null;

            try
            {
                using (var cert = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, openFlags))
                {
                    rsaPrivate = cert.GetRSAPrivateKey();
                    rsaPublic = cert.GetRSAPublicKey();
                }

                // Try really hard to ensure that if any SafeHandles are mis-tracked that we'll fail.
                // The first version of this test passed erroneously, then encountered errors after
                // the sleep was added, so please don't remove it.
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Task.Delay(3000).GetAwaiter().GetResult();
                GC.Collect();
                GC.WaitForPendingFinalizers();

                byte[] data = { 0, 1, 1, 2, 3, 5, 8, 13 };
                byte[] signature = rsaPrivate.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.True(rsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
            finally
            {
                rsaPrivate?.Dispose();
                rsaPublic?.Dispose();
            }
        }

        [Theory]
        [ActiveIssue(2745, PlatformID.AnyUnix)]
        [OuterLoop(/* The test sleeps */)]
        [InlineData(X509KeyStorageFlags.DefaultKeySet)]
        [InlineData(X509KeyStorageFlags.EphemeralKeys)]
        public static void UseRSAKeyAfterCertDispose_MultiCertPfx(X509KeyStorageFlags openFlags)
        {
            // Perphemeral (adj) - Portmonteau of Persisted/Permanent and Ephemeral, indicating that
            // characteristics of both persisted and ephemeral are observed.
            //
            // For the purpose of this test, it means the keyfile was written to disk then deleted when
            // the certificate reference count hit zero (the behavior from net20 when PersistedKeySet
            // was not specified).

            // This is a slightly overloaded test:
            // 1) Verifies that private keys from Perphemeral PFX imports work
            // 2) Verifies that said private keys continue to work after disposing the certificate
            // 3) Verifies that multiple calls to GetRSAPrivateKey all succeed
            // 4) Verifies that disposing any of the private keys does not invalidate all of them
            // 5) 1-4 for public keys, as well.
            // 5) Repeats 1-5 for Ephemeral keypairs
            List<RSA> rsaPublics = new List<RSA>();
            List<RSA> rsaPrivates = new List<RSA>();

            try
            {
                using (ImportedCollection ic = Cert.Import(TestData.MultiPrivateKeyPfx, null, openFlags))
                {
                    X509Certificate2Collection collection = ic.Collection;
                    Assert.InRange(collection.Count, 2, int.MaxValue);

                    for (int i = 0; i < 3; i++)
                    {
                        foreach (X509Certificate2 cert in collection)
                        {
                            RSA rsaPublic = cert.GetRSAPublicKey();
                            RSA rsaPrivate = cert.GetRSAPrivateKey();
                            Assert.NotNull(rsaPublic);
                            Assert.NotNull(rsaPrivate);

                            rsaPublics.Add(rsaPublic);
                            rsaPrivates.Add(rsaPrivate);
                        }
                    }
                }

                Assert.Equal(rsaPublics.Count, rsaPrivates.Count);

                // Try really hard to ensure that if any SafeHandles are mis-tracked that we'll fail.
                // The first version of this test passed erroneously, then encountered errors after
                // the sleep was added, so please don't remove it.
                GC.Collect();
                GC.WaitForPendingFinalizers();
                Task.Delay(3000).GetAwaiter().GetResult();
                GC.Collect();
                GC.WaitForPendingFinalizers();

                byte[] data = { 0, 1, 1, 2, 3, 5, 8, 13 };

                for (int i = 0; i < rsaPublics.Count; i++)
                {
                    RSA rsaPrivate = rsaPrivates[i];
                    byte[] signature = rsaPrivate.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    rsaPrivate.Dispose();

                    RSA rsaPublic = rsaPublics[i];
                    Assert.True(rsaPublic.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                    rsaPublic.Dispose();
                }
                
            }
            finally
            {
                rsaPublics.ForEach(rsa => rsa.Dispose());
                rsaPrivates.ForEach(rsa => rsa.Dispose());
            }
        }

        [Theory]
        [PlatformSpecific(PlatformID.Windows)]
        [InlineData(false)]
        [InlineData(true)]
        public static void VerifyEphemeralKeyState(bool isEphemeral)
        {
            X509KeyStorageFlags openFlags = isEphemeral ? X509KeyStorageFlags.EphemeralKeys : 0;

            using (var cert = new X509Certificate2(TestData.PfxData, TestData.PfxDataPassword, openFlags))
            using (RSA rsaPrivate = cert.GetRSAPrivateKey())
            {
                Assert.NotNull(rsaPrivate);
                AssertEphemeralCngKey(rsaPrivate, isEphemeral);
            }
        }

        private static void AssertEphemeralCngKey(RSA rsa, bool isEphemeral)
        {
            RSACng rsaCng = (RSACng)rsa;
            CngKey key = rsaCng.Key;

            if (isEphemeral)
            {
                Assert.Null(key.KeyName);
                Assert.True(key.IsEphemeral);
            }
            else
            {
                Assert.NotNull(key.KeyName);
                Assert.NotEqual(string.Empty, key.KeyName);
                Assert.False(key.IsEphemeral);
            }
        }

        // Keep the ECDsaCng-ness contained within this helper method so that it doesn't trigger a
        // FileNotFoundException on Unix.
        private static void AssertEccAlgorithm(ECDsa ecdsa, string algorithmId)
        {
            ECDsaCng cng = ecdsa as ECDsaCng;

            if (cng != null)
            {
                Assert.Equal(algorithmId, cng.Key.Algorithm.Algorithm);
            }
        }

        private static readonly byte[] s_expectedSig =
            ("44b15120b8c7de19b4968d761600ffb8c54e5d0c1bcaba0880a20ab48912c8fdfa81b28134eabf58f3211a0d1eefdaae115e7872d5a67045c3b62a5da4393940e5a496"
          + "413a6d55ea6309d0013e90657c83c6e40aa8fafeee66acbb6661c1419011e1fde6f4fcc328bd7e537e4aa2dbe216d8f1f3aa7e5ec60eb9cfdca7a41d74").HexToByteArray();
    }
}
