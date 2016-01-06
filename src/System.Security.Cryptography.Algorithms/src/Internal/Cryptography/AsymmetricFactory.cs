// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class AsymmetricFactory
    {
        private static readonly Lazy<Type> s_rsaType = new Lazy<Type>(LoadRSAType);
        private static readonly Lazy<Type> s_ecdsaType = new Lazy<Type>(LoadECDsaType);

        internal static RSA CreateRSA()
        {
            return (RSA)Create(s_rsaType);
        }

        internal static ECDsa CreateECDsa()
        {
            return (ECDsa)Create(s_ecdsaType);
        }

        private static object Create(Lazy<Type> lazyType)
        {
            Type type = lazyType.Value;

            // In Desktop this is performed by CryptoConfig.  If it cannot resolve a
            // string to a type it returns null, so we'll do the same.
            if (type == null)
            {
                return null;
            }

            return Activator.CreateInstance(type);
        }
    }
}