// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Apple;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public partial class DSA : AsymmetricAlgorithm
    {
        public static DSA Create()
        {
            return new DSAImplementation.DSASecurityTransforms();
        }

        internal static partial class DSAImplementation
        {
            // TODO: Name this for real.
            public sealed partial class DSASecurityTransforms : DSA
            {
                private KeyPair _keys;

                public DSASecurityTransforms()
                    : this(2048)
                {
                }

                public DSASecurityTransforms(int keySize)
                {
                    KeySize = keySize;
                }

                public override KeySizes[] LegalKeySizes
                {
                    get
                    {
                        return new[] { new KeySizes(minSize: 512, maxSize: 3072, skipSize: 64) };
                    }
                }

                public override int KeySize
                {
                    get
                    {
                        return base.KeySize;
                    }
                    set
                    {
                        if (KeySize == value)
                            return;

                        // Set the KeySize before freeing the key so that an invalid value doesn't throw away the key
                        base.KeySize = value;

                        _keys?.Dispose();
                        _keys = null;
                    }
                }

                public override DSAParameters ExportParameters(bool includePrivateParameters)
                {
                    KeyPair keys = GetKeys();

                    if (keys.PublicKey == null ||
                        (includePrivateParameters && keys.PrivateKey == null))
                    { 
                        throw new CryptographicException("No key handle allocated");
                    }

                    DSAParameters parameters = new DSAParameters();

                    DerSequenceReader publicKeyReader = Interop.AppleCrypto.SecKeyExport(keys.PublicKey, false);
                    publicKeyReader.ReadSubjectPublicKeyInfo(ref parameters);

                    if (includePrivateParameters)
                    {
                        DerSequenceReader privateKeyReader =
                            Interop.AppleCrypto.SecKeyExport(keys.PrivateKey, true);

                        privateKeyReader.ReadPkcs8Blob(ref parameters);
                    }

                    KeyBlobHelpers.ZeroExtend(ref parameters.G, parameters.P.Length);
                    KeyBlobHelpers.ZeroExtend(ref parameters.Y, parameters.P.Length);

                    if (includePrivateParameters)
                    {
                        KeyBlobHelpers.ZeroExtend(ref parameters.X, parameters.Q.Length);
                    }

                    return parameters;
                }

                public override void ImportParameters(DSAParameters parameters)
                {
                    if (parameters.P == null || parameters.Q == null || parameters.G == null || parameters.Y == null)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MissingFields);

                    // J is not required and is not even used on CNG blobs.
                    // It should, however, be less than P (J == (P-1) / Q).
                    // This validation check is just to maintain parity with DSACng and DSACryptoServiceProvider,
                    // which also perform this check.
                    if (parameters.J != null && parameters.J.Length >= parameters.P.Length)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedPJ);

                    int keySize = parameters.P.Length;
                    bool hasPrivateKey = parameters.X != null;

                    if (parameters.G.Length != keySize || parameters.Y.Length != keySize)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedPGY);

                    if (hasPrivateKey && parameters.X.Length != parameters.Q.Length)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedQX);

                    if (hasPrivateKey)
                    {
                        SafeSecKeyRefHandle privateKey = ImportKey(parameters);

                        DSAParameters publicOnly = parameters;
                        publicOnly.X = null;

                        SafeSecKeyRefHandle publicKey;
                        try
                        {
                            publicKey = ImportKey(publicOnly);
                        }
                        catch
                        {
                            privateKey.Dispose();
                            throw;
                        }

                        SetKey(KeyPair.PublicPrivatePair(publicKey, privateKey));
                    }
                    else
                    {
                        SafeSecKeyRefHandle publicKey = ImportKey(parameters);
                        SetKey(KeyPair.PublicOnly(publicKey));
                    }
                }

                private static SafeSecKeyRefHandle ImportKey(DSAParameters parameters)
                {
                    bool hasPrivateKey = parameters.X != null;

                    byte[] blob = hasPrivateKey ? parameters.ToPrivateKeyBlob() : parameters.ToSubjectPublicKeyInfo();
                    SafeSecKeyRefHandle keyHandle;
                    int osStatus;

                    int ret = Interop.AppleCrypto.DsaImportEphemeralKey(
                        blob,
                        blob.Length,
                        hasPrivateKey,
                        out keyHandle,
                        out osStatus);

                    if (ret == 1 && !keyHandle.IsInvalid)
                    {
                        return keyHandle;
                    }

                    if (ret == 0)
                    {
                        // TODO: Is there a better OSStatus lookup?
                        throw Interop.AppleCrypto.CreateExceptionForCCError(osStatus, "OSStatus");
                    }

                    Debug.Fail($"RsaImportEphemeralKey returned {ret}");
                    throw new CryptographicException();
                }

                public override byte[] CreateSignature(byte[] hash)
                {
                    if (hash == null)
                        throw new ArgumentNullException(nameof(hash));

                    KeyPair keys = GetKeys();

                    if (keys.PrivateKey == null)
                    {
                        throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                    }

                    byte[] derFormatSignature = Interop.AppleCrypto.DsaSign(keys.PrivateKey, hash);
                    byte[] ieeeFormatSignature = OpenSslAsymmetricAlgorithmCore.ConvertDerToIeee1363(
                        derFormatSignature,
                        0,
                        derFormatSignature.Length,
                        20*8);

                    return ieeeFormatSignature;
                }

                public override bool VerifySignature(byte[] hash, byte[] signature)
                {
                    if (hash == null)
                        throw new ArgumentNullException(nameof(hash));
                    if (signature == null)
                        throw new ArgumentNullException(nameof(signature));

                    byte[] derFormatSignature = OpenSslAsymmetricAlgorithmCore.ConvertIeee1363ToDer(signature);

                    return Interop.AppleCrypto.DsaVerify(
                        GetKeys().PublicKey,
                        hash,
                        derFormatSignature);
                }

                protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
                {
                    return OpenSslAsymmetricAlgorithmCore.HashData(data, offset, count, hashAlgorithm);
                }

                protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
                {
                    return OpenSslAsymmetricAlgorithmCore.HashData(data, hashAlgorithm);
                }

                protected override void Dispose(bool disposing)
                {
                    if (disposing)
                    {
                        _keys?.Dispose();
                        _keys = null;
                    }

                    base.Dispose(disposing);
                }

                private KeyPair GetKeys()
                {
                    KeyPair current = _keys;

                    if (current != null)
                    {
                        return current;
                    }

                    // macOS 10.11 and macOS 10.12 declare DSA invalid for key generation.
                    // Rather than write code which might or might not work, returning
                    // (OSStatus)-4 (errSecUnimplemented), just make the exception occur here.
                    //
                    // When the native code can be verified, then it can be added.
                    throw new PlatformNotSupportedException("DSA Key Generation is not supported");
                }

                private void SetKey(KeyPair newKeyPair)
                {
                    KeyPair current = _keys;
                    _keys = newKeyPair;
                    current?.Dispose();

                    if (newKeyPair != null)
                    {
                        int size = Interop.AppleCrypto.RsaGetKeySizeInBits(newKeyPair.PublicKey);
                        KeySizeValue = size;
                    }
                }
            }
        }
    }

    internal static class KeyBlobHelpers
    {
        internal static void ZeroExtend(ref byte[] blob, int minLength)
        {
            Debug.Assert(blob != null);

            if (blob.Length >= minLength)
            {
                return;
            }

            byte[] newBlob = new byte[minLength];
            Buffer.BlockCopy(blob, 0, newBlob, minLength - blob.Length, blob.Length);
            blob = newBlob;
        }
    }

    internal static class DsaKeyBlobHelpers
    {
        private static Oid s_idDsa = new Oid("1.2.840.10040.4.1");

        internal static void ReadSubjectPublicKeyInfo(this DerSequenceReader keyInfo, ref DSAParameters parameters)
        {
            // SubjectPublicKeyInfo::= SEQUENCE  {
            //    algorithm AlgorithmIdentifier,
            //    subjectPublicKey     BIT STRING  }
            DerSequenceReader algorithm = keyInfo.ReadSequence();
            string algorithmOid = algorithm.ReadOidAsString();

            // EC Public Key
            if (algorithmOid != s_idDsa.Value)
            {
                throw new CryptographicException(algorithmOid);
            }

            // Dss-Parms ::= SEQUENCE {
            //   p INTEGER,
            //   q INTEGER,
            //   g INTEGER
            // }

            DerSequenceReader algParameters = algorithm.ReadSequence();
            parameters.P = algParameters.ReadIntegerBytes();
            parameters.Q = algParameters.ReadIntegerBytes();
            parameters.G = algParameters.ReadIntegerBytes();

            if (algorithm.PeekTag() != (int)DerSequenceReader.DerTag.ObjectIdentifier)
            {
                // Only named curves are supported
                throw new PlatformNotSupportedException();
            }

            byte[] publicKeyBlob = keyInfo.ReadBitString();
            DerSequenceReader privateKeyReader = DerSequenceReader.CreateForPayload(publicKeyBlob);
            parameters.Y = privateKeyReader.ReadIntegerBytes();

            // We don't care about the rest of the blob here, but it's expected to not exist.
        }

        internal static byte[] ToSubjectPublicKeyInfo(this DSAParameters parameters)
        {
            // SubjectPublicKeyInfo::= SEQUENCE  {
            //    algorithm AlgorithmIdentifier,
            //    subjectPublicKey     BIT STRING  }

            // Dss-Parms ::= SEQUENCE {
            //   p INTEGER,
            //   q INTEGER,
            //   g INTEGER
            // }

            return DerEncoder.ConstructSequence(
                DerEncoder.ConstructSegmentedSequence(
                    DerEncoder.SegmentedEncodeOid(s_idDsa),
                    DerEncoder.ConstructSegmentedSequence(
                        DerEncoder.SegmentedEncodeUnsignedInteger(parameters.P),
                        DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Q),
                        DerEncoder.SegmentedEncodeUnsignedInteger(parameters.G)
                    )
                ),
                DerEncoder.SegmentedEncodeBitString(
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Y))
            );
        }

        internal static void ReadPkcs8Blob(this DerSequenceReader reader, ref DSAParameters parameters)
        {
            // Since the PKCS#8 blob for DSS/DSA does not include the public key (Y) this
            // structure is only read after filling the public half.
            Debug.Assert(parameters.P != null);
            Debug.Assert(parameters.Q != null);
            Debug.Assert(parameters.G != null);
            Debug.Assert(parameters.Y != null);

            // OneAsymmetricKey ::= SEQUENCE {
            //   version                   Version,
            //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
            //   privateKey                PrivateKey,
            //   attributes            [0] Attributes OPTIONAL,
            //   ...,
            //   [[2: publicKey        [1] PublicKey OPTIONAL ]],
            //   ...
            // }
            //
            // PrivateKeyInfo ::= OneAsymmetricKey
            //
            // PrivateKey ::= OCTET STRING

            int version = reader.ReadInteger();

            // We understand both version 0 and 1 formats,
            // which are now known as v1 and v2, respectively.
            if (version > 1)
            {
                throw new CryptographicException();
            }

            {
                // Ensure we're reading DSA, extract the parameters
                DerSequenceReader algorithm = reader.ReadSequence();

                string algorithmOid = algorithm.ReadOidAsString();

                if (algorithmOid != s_idDsa.Value)
                {
                    throw new CryptographicException(algorithmOid);
                }

                // The Dss-Params SEQUENCE is present here, but not needed since
                // we got it from the public key already.
            }

            byte[] privateKeyBlob = reader.ReadOctetString();
            DerSequenceReader privateKeyReader = DerSequenceReader.CreateForPayload(privateKeyBlob);
            parameters.X = privateKeyReader.ReadIntegerBytes();
        }

        internal static byte[] ToPrivateKeyBlob(this DSAParameters parameters)
        {
            Debug.Assert(parameters.X != null);

            // DSAPrivateKey ::= SEQUENCE(
            //   version INTEGER,
            //   p INTEGER,
            //   q INTEGER,
            //   g INTEGER,
            //   y INTEGER,
            //   x INTEGER,
            // )

            return DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(new byte[] { 0 }),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.P),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Q),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.G),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Y),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.X));
        }
    }
}
