// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using Xunit;

namespace System.Security.Cryptography.Algorithms.Tests
{
    public class AsymmetricAlgorithmFactoryTests
    {
        [Fact]
        public static void CheckRSACreate()
        {
            RSA rsa = RSA.Create();
            Assert.NotNull(rsa);
            Assert.Equal(2048, rsa.KeySize);
        }

        [Fact]
        public static void CheckECDsaCreate()
        {
            ECDsa ecdsa = ECDsa.Create();
            Assert.NotNull(ecdsa);
            Assert.Equal(521, ecdsa.KeySize);
        }
    }
}