using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests
{
    public class X509StoreTests
    {
        /// <summary>
        /// This test is for excerising X509Store and X509Chain code without actually installing any certificate 
        /// </summary>
        [Fact]
        [ActiveIssue(1993, PlatformID.AnyUnix)]
        public static void X509CertStoreChain()
        {
            X509Store store = new X509Store("My", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            // can't guarantee there is a certificate in store
            if (store.Certificates.Count > 0)
            {
                X509Chain chain = new X509Chain();
                Assert.NotNull(chain.SafeHandle);
                Assert.Same(chain.SafeHandle, chain.SafeHandle);
                Assert.True(chain.SafeHandle.IsInvalid);

                foreach (X509Certificate2 c in store.Certificates)
                {
                    // can't guarantee success, so no Assert 
                    if (chain.Build(c))
                    {
                        foreach (X509ChainElement k in chain.ChainElements)
                        {
                            Assert.NotNull(k.Certificate.IssuerName.Name);
                        }
                    }
                }
            }
        }

        [Fact]
        [ActiveIssue(1993, PlatformID.AnyUnix)]
        public static void X509Cert2ToStringVerbose()
        {
            X509Store store = new X509Store("My", StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);

            foreach (X509Certificate2 c in store.Certificates)
            {
                Assert.False(string.IsNullOrWhiteSpace(c.ToString(true)));
            }
        }

        [Fact]
        public static void OpenMyStore()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
            }
        }

        [Fact]
        public static void ReadMyCertificates()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                int certCount = store.Certificates.Count;

                // This assert is just so certCount appears to be used, the test really
                // is that store.get_Certificates didn't throw.
                Assert.True(certCount >= 0);
            }
        }

        [Fact]
        public static void OpenNotExistant()
        {
            using (X509Store store = new X509Store(Guid.NewGuid().ToString("N"), StoreLocation.CurrentUser))
            {
                Assert.Throws<CryptographicException>(() => store.Open(OpenFlags.OpenExistingOnly));
            }
        }

        [Fact]
        public static void AddReadOnlyThrows()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (X509Certificate2 cert = new X509Certificate2(TestData.MsCertificate))
            {
                store.Open(OpenFlags.ReadOnly);
                Assert.Throws<CryptographicException>(() => store.Add(cert));
            }
        }

        [Fact]
        public static void RemoveReadOnlyThrowsWhenFound()
        {
            // This test is unfortunate, in that it will mostly never test.
            // In order to do so it would have to open the store ReadWrite, put in a known value,
            // and call Remove on a ReadOnly copy.
            //
            // Just calling Remove on the first item found could also work (when the store isn't empty),
            // but if it fails the cost is too high.
            //
            // So what's the purpose of this test, you ask? To record why we're not unit testing it.
            // And someone could test it manually if they wanted.
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (X509Certificate2 cert = new X509Certificate2(TestData.MsCertificate))
            {
                store.Open(OpenFlags.ReadOnly);

                if (store.Certificates.Contains(cert))
                {
                    Assert.Throws<CryptographicException>(() => store.Remove(cert));
                }
            }
        }

        [Fact]
        public static void EnumerateClosedIsEmpty()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                int count = store.Certificates.Count;
                Assert.Equal(0, count);
            }
        }

        [Fact]
        public static void AddClosedThrows()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (X509Certificate2 cert = new X509Certificate2(TestData.MsCertificate))
            {
                Assert.Throws<CryptographicException>(() => store.Add(cert));
            }
        }

        [Fact]
        public static void RemoveClosedThrows()
        {
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            using (X509Certificate2 cert = new X509Certificate2(TestData.MsCertificate))
            {
                Assert.Throws<CryptographicException>(() => store.Remove(cert));
            }
        }
    }
}