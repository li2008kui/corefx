// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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

            SafeCreateHandle privateKey;

            SafeSecCertificateHandle certHandle =
                Interop.AppleCrypto.X509ImportCertificate(rawData, out privateKey);

            return new AppleCertificatePal(certHandle, privateKey);
        }

        public static ICertificatePal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            throw new NotImplementedException();
        }
    }

    internal sealed class AppleCertificatePal : ICertificatePal
    {
        private SafeSecCertificateHandle _certHandle;
        private SafeCreateHandle _privateKeyHandle;

        internal AppleCertificatePal(SafeSecCertificateHandle certHandle, SafeCreateHandle privateKey)
        {
            _certHandle = certHandle;
            _privateKeyHandle = privateKey;
        }

        public void Dispose()
        {
            _certHandle?.Dispose();
            _privateKeyHandle?.Dispose();

            _certHandle = null;
            _privateKeyHandle = null;
        }

        public bool HasPrivateKey => !(_privateKeyHandle?.IsInvalid ?? false);

        public IntPtr Handle => _certHandle?.DangerousGetHandle() ?? IntPtr.Zero;

        public string Issuer { get; }
        public string Subject { get; }
        public byte[] Thumbprint { get; }
        public string KeyAlgorithm { get; }
        public byte[] KeyAlgorithmParameters { get; }
        public byte[] PublicKeyValue { get; }
        public byte[] SerialNumber { get; }
        public string SignatureAlgorithm { get; }
        public DateTime NotAfter { get; }
        public DateTime NotBefore { get; }

        public byte[] RawData => _certHandle == null ? null : Interop.AppleCrypto.X509GetRawData(_certHandle);

        public int Version { get; }
        public bool Archived { get; set; }
        public string FriendlyName { get; set; }
        public X500DistinguishedName SubjectName { get; }
        public X500DistinguishedName IssuerName { get; }
        public IEnumerable<X509Extension> Extensions { get; }
        public AsymmetricAlgorithm GetPrivateKey()
        {
            throw new NotImplementedException();
        }

        public RSA GetRSAPrivateKey()
        {
            throw new NotImplementedException();
        }

        public DSA GetDSAPrivateKey()
        {
            throw new NotImplementedException();
        }

        public ECDsa GetECDsaPrivateKey()
        {
            throw new NotImplementedException();
        }

        public string GetNameInfo(X509NameType nameType, bool forIssuer)
        {
            throw new NotImplementedException();
        }

        public void AppendPrivateKeyInfo(StringBuilder sb)
        {
            throw new NotImplementedException();
        }
    }
}
