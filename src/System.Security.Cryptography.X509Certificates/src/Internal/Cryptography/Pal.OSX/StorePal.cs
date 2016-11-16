// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class StorePal
    {
        public static IStorePal FromHandle(IntPtr storeHandle)
        {
            throw new PlatformNotSupportedException();
        }

        public static ILoaderPal FromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            throw new NotImplementedException();
        }

        public static ILoaderPal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            throw new NotImplementedException();
        }

        public static IExportPal FromCertificate(ICertificatePal cert)
        {
            throw new NotImplementedException();
        }

        public static IExportPal LinkFromCertificateCollection(X509Certificate2Collection certificates)
        {
            throw new NotImplementedException();
        }

        public static IStorePal FromSystemStore(string storeName, StoreLocation storeLocation, OpenFlags openFlags)
        {
            throw new NotImplementedException();
        }
    }
}
