// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal
    {
        public static ICertificatePal FromHandle(IntPtr handle)
        {
            throw new NotImplementedException();
        }

        public static ICertificatePal FromOtherCert(X509Certificate cert)
        {
            Debug.Assert(cert.Pal != null);

            throw new NotImplementedException();
        }

        public static ICertificatePal FromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            throw new NotImplementedException();
        }

        public static ICertificatePal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            throw new NotImplementedException();
        }
    }
}
