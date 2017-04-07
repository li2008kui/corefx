// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    /// <summary>
    /// Represents an abstraction over the PKCS#10 CertificationRequestInfo and the X.509 TbsCertificate,
    /// allowing callers to create self-signed or chain-signed X.509 Public-Key Certificates, as well as
    /// create a certificate signing request blob to send to a Certificate Authority (CA).
    /// </summary>
    public sealed class CertificateRequest
    {
        private readonly AsymmetricAlgorithm _key;
        private readonly X509SignatureGenerator _generator;

        /// <summary>
        /// The X.500 Distinguished Name to use as the Subject in a created certificate or certificate request.
        /// </summary>
        public X500DistinguishedName Subject { get; }

        /// <summary>
        /// The X.509 Certificate Extensions to include in the certificate or certificate request.
        /// </summary>
        public ICollection<X509Extension> CertificateExtensions { get; } = new List<X509Extension>();

        /// <summary>
        /// A <see cref="PublicKey" /> representation of the public key for the certificate or certificate request.
        /// 
        /// For self-signed certificates and certificate requests this value may be <c>null</c> to signal that the
        /// value from the <see cref="X509SignatureGenerator" /> should be used. For chain-signed certificates this
        /// value must not be <c>null</c>.
        /// </summary>
        public PublicKey PublicKey { get; }

        public HashAlgorithmName HashAlgorithm { get; }

        public CertificateRequest(string subjectDistinguishedName, DSA key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectDistinguishedName == null)
                throw new ArgumentNullException(nameof(subjectDistinguishedName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = new X500DistinguishedName(subjectDistinguishedName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForDSA(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(X500DistinguishedName subjectName, DSA key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForDSA(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(string subjectDistinguishedName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectDistinguishedName == null)
                throw new ArgumentNullException(nameof(subjectDistinguishedName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = new X500DistinguishedName(subjectDistinguishedName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(X500DistinguishedName subjectName, ECDsa key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForECDsa(key);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(string subjectDistinguishedName, RSA key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectDistinguishedName == null)
                throw new ArgumentNullException(nameof(subjectDistinguishedName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = new X500DistinguishedName(subjectDistinguishedName);

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(X500DistinguishedName subjectName, RSA key, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            Subject = subjectName;

            _key = key;
            _generator = X509SignatureGenerator.CreateForRSA(key, RSASignaturePadding.Pkcs1);
            PublicKey = _generator.PublicKey;
            HashAlgorithm = hashAlgorithm;
        }

        public CertificateRequest(X500DistinguishedName subjectName, PublicKey publicKey, HashAlgorithmName hashAlgorithm)
        {
            if (subjectName == null)
                throw new ArgumentNullException(nameof(subjectName));
            if (publicKey == null)
                throw new ArgumentNullException(nameof(publicKey));

            Subject = subjectName;
            PublicKey = publicKey;
            HashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest object representating the current state
        /// of this object.
        /// </summary>
        /// <returns>A DER-encoded certificate signing request.</returns>
        /// <remarks>
        ///   When submitting a certificate signing request via a web browser, or other graphical or textual
        ///   interface, the input is frequently expected to be in the PEM (Privacy Enhanced Mail) format,
        ///   instead of the DER binary format. To convert the return value to PEM format, make a string
        ///   consisting of <c>-----BEGIN CERTIFICATE REQUEST-----</c>, a newline, the Base-64-encoded
        ///   representation of the request (by convention, linewrapped at 64 characters), a newline,
        ///   and <c>-----END CERTIFICATE REQUEST-----</c>.
        /// 
        ///   <code><![CDATA[
        ///     public static string PemEncodeSigningRequest(CertificateRequest request, PkcsSignatureGenerator generator)
        ///     {
        ///         byte[] pkcs10 = request.EncodeSigningRequest(generator);
        ///         StringBuilder builder = new StringBuilder();
        ///     
        ///         builder.AppendLine("-----BEGIN CERTIFICATE REQUEST-----");
        ///     
        ///         string base64 = Convert.ToBase64String(pkcs10);
        ///     
        ///         int offset = 0;
        ///         const int LineLength = 64;
        ///     
        ///         while (offset < base64.Length)
        ///         {
        ///             int lineEnd = Math.Min(offset + LineLength, base64.Length);
        ///             builder.AppendLine(base64.Substring(offset, lineEnd - offset));
        ///             offset = lineEnd;
        ///         }
        ///     
        ///         builder.AppendLine("-----END CERTIFICATE REQUEST-----");
        ///         return builder.ToString();
        ///     }
        ///   ]]></code>
        /// </remarks>
        public byte[] EncodePkcs10SigningRequest()
        {
            if (_generator == null)
                throw new InvalidOperationException("wrong ctor");

            return EncodePkcs10SigningRequest(_generator);
        }

        /// <summary>
        /// Create an ASN.1 DER-encoded PKCS#10 CertificationRequest object representating the current state
        /// of this object.
        /// </summary>
        /// <param name="signatureGenerator">
        ///   A <see cref="X509SignatureGenerator"/> with which to sign the request.
        /// </param>
        public byte[] EncodePkcs10SigningRequest(X509SignatureGenerator signatureGenerator)
        {
            if (signatureGenerator == null)
                throw new ArgumentNullException(nameof(signatureGenerator));

            List<X501Attribute> attributes = new List<X501Attribute>(2);

            if (CertificateExtensions.Count > 0)
            {
                attributes.Add(new Pkcs9ExtensionRequest(CertificateExtensions));
            }

            // Allow the public key to mismatch, for Diffie-Hellman, or other types of non-signing keys.
            PublicKey publicKey = PublicKey ?? signatureGenerator.PublicKey;
            var requestInfo = new Pkcs10CertificationRequestInfo(Subject, publicKey, attributes);
            return requestInfo.ToPkcs10Request(signatureGenerator, HashAlgorithm);
        }

        /// <summary>
        /// Create a self-signed certificate using the established subject, optional attributes, and
        /// optional public key value which has a <see cref="X509Certificate2.NotBefore" /> value of
        /// the current time and a <see cref="X509Certificate2.NotAfter" /> value computed via the
        /// specified <paramref name="validityPeriod"/>.
        /// </summary>
        /// <param name="validityPeriod">
        ///   The interval for which the certificate should be considerd valid.
        ///   While values smaller than a second will be used in the computation of the NotAfter value,
        ///   validity dates within certificates are truncated to the second.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException">
        ///   <paramref name="validityPeriod"/> represents negative amount of time.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///   Other errors during the certificate creation process.
        /// </exception>
        public X509Certificate2 SelfSign(TimeSpan validityPeriod)
        {
            if (validityPeriod < TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(validityPeriod));

            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore + validityPeriod;

            return SelfSign(notBefore, notAfter);
        }

        /// <summary>
        /// Create a self-signed certificate using the established subject, optional attributes, and
        /// optional public key value which has a <see cref="X509Certificate2.NotBefore" /> value of
        /// the current time and a <see cref="X509Certificate2.NotAfter" /> value computed via the
        /// specified validity fields (<paramref name="notBefore" /> and <paramref name="notAfter"/>).
        /// </summary>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <returns>
        ///   An <see cref="X509Certificate2"/> with the specified values. The returned object will
        ///   assert <see cref="X509Certificate2.HasPrivateKey" />.
        /// </returns>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notAfter"/>.
        /// </exception>
        /// <exception cref="InvalidOperationException"><see cref="Subject"/> is null.</exception>
        /// <exception cref="CryptographicException">
        ///   Other errors during the certificate creation process.
        /// </exception>
        public X509Certificate2 SelfSign(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            if (notAfter < notBefore)
                throw new ArgumentException("SR.Cryptography_X509_DatesReversed");
            if (_key == null)
                throw new InvalidOperationException("No key defined");

            Debug.Assert(_generator != null);

            TbsCertificate tbsCertificate = new TbsCertificate();
            tbsCertificate.Subject = Subject;

            // Respect the PublicKey property, if set. It should only differ on an optional DER-NULL.
            tbsCertificate.PublicKey = PublicKey;
            tbsCertificate.Extensions.AddRange(CertificateExtensions);
            tbsCertificate.NotBefore = notBefore;
            tbsCertificate.NotAfter = notAfter;

            byte[] certBytes = tbsCertificate.Sign(_generator, HashAlgorithm);

            try
            {
                X509Certificate2 certificate = new X509Certificate2(certBytes);

                RSA rsa = _key as RSA;

                if (rsa != null)
                {
                    return certificate.CreateCopyWithPrivateKey(rsa);
                }

                ECDsa ecdsa = _key as ECDsa;

                if (ecdsa != null)
                {
                    return certificate.CreateCopyWithPrivateKey(ecdsa);
                }

                DSA dsa = _key as DSA;

                if (dsa != null)
                {
                    return certificate.CreateCopyWithPrivateKey(dsa);
                }
            }
            catch
            {
                Console.WriteLine(
                    "-----BEGIN CERTIFICATE-----" + Environment.NewLine +
                    Convert.ToBase64String(certBytes) + Environment.NewLine +
                    "-----END CERTIFICATE-----");

                throw;
            }

            Debug.Fail($"Key was of no known type: {_key?.GetType().FullName ?? "null"}");
            throw new CryptographicException();
        }

        public X509Certificate2 Sign(X509Certificate2 issuerCertificate, TimeSpan validityPeriod, byte[] serialNumber)
        {
            if (validityPeriod < TimeSpan.Zero)
                throw new ArgumentOutOfRangeException(nameof(validityPeriod));

            DateTimeOffset notBefore = DateTimeOffset.UtcNow;
            DateTimeOffset notAfter = notBefore + validityPeriod;

            return Sign(issuerCertificate, notBefore, notAfter, serialNumber);
        }

        public X509Certificate2 Sign(
            X509Certificate2 issuerCertificate,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            if (issuerCertificate == null)
                throw new ArgumentNullException(nameof(issuerCertificate));
            if (!issuerCertificate.HasPrivateKey)
                throw new ArgumentException("SR.Cryptography_X509_IssuerRequiresPrivateKey", nameof(issuerCertificate));

            AsymmetricAlgorithm key = null;
            string keyAlgorithm = issuerCertificate.GetKeyAlgorithm();
            X509SignatureGenerator generator;

            switch (keyAlgorithm)
            {
                case Oids.RsaRsa:
                    RSA rsa = issuerCertificate.GetRSAPrivateKey();
                    key = rsa;
                    generator = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
                    break;
                case Oids.Ecc:
                    ECDsa ecdsa = issuerCertificate.GetECDsaPrivateKey();
                    key = ecdsa;
                    generator = X509SignatureGenerator.CreateForECDsa(ecdsa);
                    break;
                case Oids.DsaDsa:
                    DSA dsa = issuerCertificate.GetDSAPrivateKey();
                    key = dsa;
                    generator = X509SignatureGenerator.CreateForDSA(dsa);
                    break;
                default:
                    throw new ArgumentException(
                        "SR.Format(SR.Cryptography_UnknownKeyAlgorithm, keyAlgorithm)",
                        nameof(issuerCertificate));
            }

            using (key)
            {
                return Sign(issuerCertificate.SubjectName, generator, notBefore, notAfter, serialNumber);
            }
        }

        /// <summary>
        /// Sign the current certificate request to create a chain-signed or self-signed certificate.
        /// </summary>
        /// <param name="issuerName">The X500DistinguishedName for the Issuer</param>
        /// <param name="generator">
        ///   An <see cref="X509SignatureGenerator"/> representing the issuing certificate authority.
        /// </param>
        /// <param name="notBefore">
        ///   The oldest date and time where this certificate is considered valid.
        ///   Typically <see cref="DateTimeOffset.UtcNow"/>, plus or minus a few seconds.
        /// </param>
        /// <param name="notAfter">
        ///   The date and time where this certificate is no longer considered valid.
        /// </param>
        /// <param name="serialNumber">
        ///   The serial number to use for the new certificate. This value should be unique per issuer.
        ///   The value is interpreted as an unsigned (big) integer in big endian byte ordering.
        /// </param>
        /// <returns>
        ///   The ASN.1 DER-encoded certificate, suitable to be passed to <see cref="X509Certificate2(byte[])"/>.
        /// </returns>
        /// <exception cref="ArgumentNullException"><paramref name="issuerName"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="generator"/> is null.</exception>
        /// <exception cref="ArgumentException">
        ///   <paramref name="notAfter"/> represents a date and time before <paramref name="notAfter"/>.
        /// </exception>
        /// <exception cref="ArgumentException"><paramref name="serialNumber"/> is null or has length 0.</exception>
        /// <exception cref="InvalidOperationException"><see cref="Subject"/> is null.</exception>
        /// <exception cref="InvalidOperationException"><see cref="PublicKey"/> is null.</exception>
        /// <exception cref="CryptographicException">Any error occurs during the signing operation.</exception>
        public X509Certificate2 Sign(
            X500DistinguishedName issuerName,
            X509SignatureGenerator generator,
            DateTimeOffset notBefore,
            DateTimeOffset notAfter,
            byte[] serialNumber)
        {
            if (issuerName == null)
                throw new ArgumentNullException(nameof(issuerName));
            if (generator == null)
                throw new ArgumentNullException(nameof(generator));
            if (notAfter < notBefore)
                throw new ArgumentException("SR.Cryptography_X509_DatesReversed");
            if (serialNumber == null || serialNumber.Length < 1)
                throw new ArgumentException(SR.Arg_EmptyOrNullArray, nameof(serialNumber));

            TbsCertificate tbsCertificate = new TbsCertificate
            {
                Subject = Subject,
                SerialNumber = serialNumber,
                Issuer = issuerName,
                PublicKey = PublicKey,
                NotBefore = notBefore,
                NotAfter = notAfter,
            };

            tbsCertificate.Extensions.AddRange(CertificateExtensions);

            return new X509Certificate2(tbsCertificate.Sign(generator, HashAlgorithm));
        }
    }
}
