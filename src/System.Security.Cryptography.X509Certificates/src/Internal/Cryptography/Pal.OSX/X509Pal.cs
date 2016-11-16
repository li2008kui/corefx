// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        public static IX509Pal Instance = new Stub();

        private X509Pal()
        {
        }

        private class Stub : IX509Pal
        {
            public AsymmetricAlgorithm DecodePublicKey(Oid oid, byte[] encodedKeyValue, byte[] encodedParameters,
                ICertificatePal certificatePal)
            {
                throw new System.NotImplementedException();
            }

            public string X500DistinguishedNameDecode(byte[] encodedDistinguishedName, X500DistinguishedNameFlags flag)
            {
                throw new System.NotImplementedException();
            }

            public byte[] X500DistinguishedNameEncode(string distinguishedName, X500DistinguishedNameFlags flag)
            {
                throw new System.NotImplementedException();
            }

            public string X500DistinguishedNameFormat(byte[] encodedDistinguishedName, bool multiLine)
            {
                throw new System.NotImplementedException();
            }

            public X509ContentType GetCertContentType(byte[] rawData)
            {
                throw new System.NotImplementedException();
            }

            public X509ContentType GetCertContentType(string fileName)
            {
                throw new System.NotImplementedException();
            }

            public byte[] EncodeX509KeyUsageExtension(X509KeyUsageFlags keyUsages)
            {
                throw new System.NotImplementedException();
            }

            public void DecodeX509KeyUsageExtension(byte[] encoded, out X509KeyUsageFlags keyUsages)
            {
                throw new System.NotImplementedException();
            }

            public bool SupportsLegacyBasicConstraintsExtension { get; }

            public byte[] EncodeX509BasicConstraints2Extension(bool certificateAuthority, bool hasPathLengthConstraint,
                int pathLengthConstraint)
            {
                throw new System.NotImplementedException();
            }

            public void DecodeX509BasicConstraintsExtension(byte[] encoded, out bool certificateAuthority, out bool hasPathLengthConstraint,
                out int pathLengthConstraint)
            {
                throw new System.NotImplementedException();
            }

            public void DecodeX509BasicConstraints2Extension(byte[] encoded, out bool certificateAuthority,
                out bool hasPathLengthConstraint, out int pathLengthConstraint)
            {
                throw new System.NotImplementedException();
            }

            public byte[] EncodeX509EnhancedKeyUsageExtension(OidCollection usages)
            {
                throw new System.NotImplementedException();
            }

            public void DecodeX509EnhancedKeyUsageExtension(byte[] encoded, out OidCollection usages)
            {
                throw new System.NotImplementedException();
            }

            public byte[] EncodeX509SubjectKeyIdentifierExtension(byte[] subjectKeyIdentifier)
            {
                throw new System.NotImplementedException();
            }

            public void DecodeX509SubjectKeyIdentifierExtension(byte[] encoded, out byte[] subjectKeyIdentifier)
            {
                throw new System.NotImplementedException();
            }

            public byte[] ComputeCapiSha1OfPublicKey(PublicKey key)
            {
                throw new System.NotImplementedException();
            }
        }
    }
}
