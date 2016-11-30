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
                Interop.AppleCrypto.X509ImportCertificate(rawData, password, out privateKey);

            return new AppleCertificatePal(certHandle, privateKey);
        }

        public static ICertificatePal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);
            return FromBlob(fileBytes, password, keyStorageFlags);
        }
    }

    internal sealed class AppleCertificatePal : ICertificatePal
    {
        private SafeSecCertificateHandle _certHandle;
        private SafeCreateHandle _privateKeyHandle;
        private CertificateData _certData;
        private bool _readCertData;

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

        internal SafeSecCertificateHandle SafeHandle => _certHandle;

        public bool HasPrivateKey => !(_privateKeyHandle?.IsInvalid ?? false);

        public IntPtr Handle => _certHandle?.DangerousGetHandle() ?? IntPtr.Zero;

        public string Issuer => IssuerName.Name;

        public string Subject => SubjectName.Name;

        public string KeyAlgorithm
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKeyAlgorithm.AlgorithmId;
            }
        }

        public byte[] KeyAlgorithmParameters
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKeyAlgorithm.Parameters;
            }
        }

        public byte[] PublicKeyValue
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKey;
            }
        }

        public byte[] SerialNumber
        {
            get
            {
                EnsureCertData();
                byte[] serial = _certData.SerialNumber;
                Array.Reverse(serial);
                return serial;
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                EnsureCertData();
                return _certData.SignatureAlgorithm.AlgorithmId;
            }
        }

        public string FriendlyName
        {
            get { return ""; }
            set { throw new PlatformNotSupportedException(); }
        }

        public int Version
        {
            get
            {
                EnsureCertData();
                return _certData.Version + 1;
            }
        }

        public X500DistinguishedName SubjectName
        {
            get
            {
                EnsureCertData();
                return _certData.Subject;
            }
        }

        public X500DistinguishedName IssuerName
        {
            get
            {
                EnsureCertData();
                return _certData.Issuer;
            }
        }

        public IEnumerable<X509Extension> Extensions {
            get
            {
                EnsureCertData();
                return _certData.Extensions;
            }
        }

        public byte[] RawData
        {
            get
            {
                EnsureCertData();
                return _certData.RawData;
            }
        }

        public DateTime NotAfter
        {
            get
            {
                EnsureCertData();
                return _certData.NotAfter.ToLocalTime();
            }
        }

        public DateTime NotBefore
        {
            get
            {
                EnsureCertData();
                return _certData.NotBefore.ToLocalTime();
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350",
            Justification = "SHA1 is required for Compat")]
        public byte[] Thumbprint
        {
            get
            {
                EnsureCertData();

                using (SHA1 hash = SHA1.Create())
                {
                    return hash.ComputeHash(_certData.RawData);
                }
            }
        }

        public bool Archived
        {
            get { return false; }
            set { throw new PlatformNotSupportedException(); }
        }

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

        private void EnsureCertData()
        {
            if (_readCertData)
                return;

            Debug.Assert(!_certHandle.IsInvalid);
            _certData = new CertificateData(Interop.AppleCrypto.X509GetRawData(_certHandle));
            _readCertData = true;
        }
    }

    internal struct CertificateData
    {
        internal struct AlgorithmIdentifier
        {
            internal string AlgorithmId;
            internal byte[] Parameters;
        }

        internal byte[] RawData;
        internal byte[] SubjectPublicKeyInfo;

        internal int Version;
        internal byte[] SerialNumber;
        internal AlgorithmIdentifier TbsSignature;
        internal X500DistinguishedName Issuer;
        internal DateTime NotBefore;
        internal DateTime NotAfter;
        internal X500DistinguishedName Subject;
        internal AlgorithmIdentifier PublicKeyAlgorithm;
        internal byte[] PublicKey;
        internal byte[] IssuerUniqueId;
        internal byte[] SubjectUniqueId;
        internal List<X509Extension> Extensions;
        internal AlgorithmIdentifier SignatureAlgorithm;
        internal byte[] SignatureValue;

        internal CertificateData(byte[] rawData)
        {
            DerSequenceReader reader = new DerSequenceReader(rawData);

            DerSequenceReader tbsCertificate = reader.ReadSequence();

            if (tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag0)
            {
                DerSequenceReader version = tbsCertificate.ReadSequence();
                Version = version.ReadInteger();
            }
            else if (tbsCertificate.PeekTag() !=
                     (DerSequenceReader.ConstructedFlag | (byte)DerSequenceReader.DerTag.Sequence))
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            else
            {
                Version = 0;
            }

            if (Version < 0 || Version > 2)
                throw new CryptographicException();

            SerialNumber = tbsCertificate.ReadIntegerBytes();

            DerSequenceReader tbsSignature = tbsCertificate.ReadSequence();
            TbsSignature.AlgorithmId = tbsSignature.ReadOidAsString();
            TbsSignature.Parameters = tbsSignature.HasData ? tbsSignature.ReadNextEncodedValue() : Array.Empty<byte>();

            if (tbsSignature.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            Issuer = new X500DistinguishedName(tbsCertificate.ReadNextEncodedValue());

            DerSequenceReader validity = tbsCertificate.ReadSequence();
            NotBefore = validity.ReadX509Date();
            NotAfter = validity.ReadX509Date();

            if (validity.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            Subject = new X500DistinguishedName(tbsCertificate.ReadNextEncodedValue());

            SubjectPublicKeyInfo = tbsCertificate.ReadNextEncodedValue();
            DerSequenceReader subjectPublicKeyInfo = new DerSequenceReader(SubjectPublicKeyInfo);
            DerSequenceReader subjectKeyAlgorithm = subjectPublicKeyInfo.ReadSequence();
            PublicKeyAlgorithm.AlgorithmId = subjectKeyAlgorithm.ReadOidAsString();
            PublicKeyAlgorithm.Parameters = subjectKeyAlgorithm.HasData ? subjectKeyAlgorithm.ReadNextEncodedValue() : Array.Empty<byte>();

            if (subjectKeyAlgorithm.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            PublicKey = subjectPublicKeyInfo.ReadBitString();

            if (subjectPublicKeyInfo.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            if (tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag1)
            {
                if (Version == 0)
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

                IssuerUniqueId = tbsCertificate.ReadBitString();
            }
            else
            {
                IssuerUniqueId = null;
            }

            if (tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag2)
            {
                if (Version == 0)
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

                SubjectUniqueId = tbsCertificate.ReadBitString();
            }
            else
            {
                SubjectUniqueId = null;
            }

            Extensions = new List<X509Extension>();

            if (tbsCertificate.PeekTag() == DerSequenceReader.ContextSpecificConstructedTag3)
            {
                DerSequenceReader extensions = tbsCertificate.ReadSequence();
                extensions = extensions.ReadSequence();

                while (extensions.HasData)
                {
                    DerSequenceReader extensionReader = extensions.ReadSequence();
                    string oid = extensionReader.ReadOidAsString();
                    bool critical = false;

                    if (extensionReader.PeekTag() == (byte)DerSequenceReader.DerTag.Boolean)
                    {
                        critical = extensionReader.ReadBoolean();
                    }

                    byte[] extensionData = extensionReader.ReadOctetString();

                    Extensions.Add(new X509Extension(oid, extensionData, critical));

                    if (extensionReader.HasData)
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            if (tbsCertificate.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            DerSequenceReader signatureAlgorithm = reader.ReadSequence();
            SignatureAlgorithm.AlgorithmId = signatureAlgorithm.ReadOidAsString();
            SignatureAlgorithm.Parameters = signatureAlgorithm.HasData ? signatureAlgorithm.ReadNextEncodedValue() : Array.Empty<byte>();

            if (signatureAlgorithm.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            SignatureValue = reader.ReadBitString();

            if (reader.HasData)
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);

            RawData = rawData;
        }
    }
}
