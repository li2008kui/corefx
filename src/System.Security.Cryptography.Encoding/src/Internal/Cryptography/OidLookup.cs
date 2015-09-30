// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class OidLookup
    {
        private static readonly ConcurrentDictionary<string, string> s_lateBoundOidToFriendlyName =
            new ConcurrentDictionary<string, string>();

        private static readonly ConcurrentDictionary<string, string> s_lateBoundFriendlyNameToOid =
            new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        //
        // Attempts to map a friendly name to an OID. Returns null if not a known name.
        //
        public static string ToFriendlyName(string oid, OidGroup oidGroup, bool fallBackToAllGroups)
        {
            if (oid == null)
                throw new ArgumentNullException("oid");

            string mappedName;
            bool shouldUseCache = ShouldUseCache(oidGroup);

            // On Unix shouldUseCache is always true, so no matter what OidGroup is passed in the Windows
            // friendly name will be returned.
            //
            // On Windows shouldUseCache is only true for OidGroup.All, because otherwise the OS may filter
            // out the answer based on the group criteria.
            if (shouldUseCache)
            {
                if (s_oidToFriendlyName.TryGetValue(oid, out mappedName) ||
                    s_compatOids.TryGetValue(oid, out mappedName) ||
                    s_lateBoundOidToFriendlyName.TryGetValue(oid, out mappedName))
                {
                    return mappedName;
                }
            }

            mappedName = NativeOidToFriendlyName(oid, oidGroup, fallBackToAllGroups);

            if (shouldUseCache && mappedName != null)
            {
                s_lateBoundOidToFriendlyName.TryAdd(oid, mappedName);

                // Don't add the reverse here.  Just because oid => name doesn't mean name => oid.
                // And don't bother doing the reverse lookup proactively, just wait until they ask for it.
            }

            return mappedName;
        }

        //
        // Attempts to retrieve the friendly name for an OID. Returns null if not a known or valid OID.
        //
        public static string ToOid(string friendlyName, OidGroup oidGroup, bool fallBackToAllGroups)
        {
            if (friendlyName == null)
                throw new ArgumentNullException("friendlyName");

            string mappedOid;
            bool shouldUseCache = ShouldUseCache(oidGroup);

            if (shouldUseCache)
            {
                if (s_friendlyNameToOid.TryGetValue(friendlyName, out mappedOid) ||
                    s_lateBoundFriendlyNameToOid.TryGetValue(friendlyName, out mappedOid))
                {
                    return mappedOid;
                }
            }

            mappedOid = NativeFriendlyNameToOid(friendlyName, oidGroup, fallBackToAllGroups);

            if (shouldUseCache && mappedOid != null)
            {
                s_lateBoundFriendlyNameToOid.TryAdd(friendlyName, mappedOid);

                // Don't add the reverse here.  Friendly Name => OID is a case insensitive search,
                // so the casing provided as input here may not be the 'correct' one.  Just let
                // ToFriendlyName capture the response and cache it itself.
            }

            return mappedOid;
        }

        // This table was originally built by extracting every szOID #define out of wincrypt.h,
        // and running them through new Oid(string) on Windows 10.
        //
        // Approximately 155 OIDs from that extraction pattern did not result in a FriendlyName value,
        // and are excluded from this table.
        //
        // Certainly other OIDs exist, and have names, but they aren't common enough to have an identifier
        // in wincrypt.h.
        //
        // Sometimes wincrypt.h has more than one OID which results in the same name.  The OIDs whose value
        // doesn't roundtrip (new Oid(new Oid(value).FriendlyName).Value) are contained in s_compatOids.
        //
        // X-Plat: The names (and casing) in this table come from Windows. Part of the intent of this table
        // is to prevent issues wherein an identifier is different between CoreFX\Windows and CoreFX\Unix;
        // since any existing code would be using the Windows identifier, it is the de facto standard.
        private static readonly Dictionary<string, string> s_friendlyNameToOid =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "3des", "1.2.840.113549.3.7" },
                { "aes128", "2.16.840.1.101.3.4.1.2" },
                { "aes128wrap", "2.16.840.1.101.3.4.1.5" },
                { "aes192", "2.16.840.1.101.3.4.1.22" },
                { "aes192wrap", "2.16.840.1.101.3.4.1.25" },
                { "aes256", "2.16.840.1.101.3.4.1.42" },
                { "aes256wrap", "2.16.840.1.101.3.4.1.45" },
                { "All application policies", "1.3.6.1.4.1.311.10.12.1" },
                { "All issuance policies", "2.5.29.32.0" },
                { "Any Purpose", "2.5.29.37.0" },
                { "Application Policies", "1.3.6.1.4.1.311.21.10" },
                { "Application Policy Constraints", "1.3.6.1.4.1.311.21.12" },
                { "Application Policy Mappings", "1.3.6.1.4.1.311.21.11" },
                { "Archived Key Certificate Hash", "1.3.6.1.4.1.311.21.16" },
                { "Authority Information Access", "1.3.6.1.5.5.7.1.1" },
                { "Authority Key Identifier", "2.5.29.35" },
                { "Basic Constraints", "2.5.29.19" },
                { "Biometric", "1.3.6.1.5.5.7.1.2" },
                { "brainpoolP160r1", "1.3.36.3.3.2.8.1.1.1" },
                { "brainpoolP160t1", "1.3.36.3.3.2.8.1.1.2" },
                { "brainpoolP192r1", "1.3.36.3.3.2.8.1.1.3" },
                { "brainpoolP192t1", "1.3.36.3.3.2.8.1.1.4" },
                { "brainpoolP224r1", "1.3.36.3.3.2.8.1.1.5" },
                { "brainpoolP224t1", "1.3.36.3.3.2.8.1.1.6" },
                { "brainpoolP256r1", "1.3.36.3.3.2.8.1.1.7" },
                { "brainpoolP256t1", "1.3.36.3.3.2.8.1.1.8" },
                { "brainpoolP320r1", "1.3.36.3.3.2.8.1.1.9" },
                { "brainpoolP320t1", "1.3.36.3.3.2.8.1.1.10" },
                { "brainpoolP384r1", "1.3.36.3.3.2.8.1.1.11" },
                { "brainpoolP384t1", "1.3.36.3.3.2.8.1.1.12" },
                { "brainpoolP512r1", "1.3.36.3.3.2.8.1.1.13" },
                { "brainpoolP512t1", "1.3.36.3.3.2.8.1.1.14" },
                { "C", "2.5.4.6" },
                { "CA Version", "1.3.6.1.4.1.311.21.1" },
                { "Certificate Extensions", "1.3.6.1.4.1.311.2.1.14" },
                { "Certificate Manifold", "1.3.6.1.4.1.311.20.3" },
                { "Certificate Policies", "2.5.29.32" },
                { "Certificate Request Agent", "1.3.6.1.4.1.311.20.2.1" },
                { "Certificate Template Information", "1.3.6.1.4.1.311.21.7" },
                { "Certificate Template Name", "1.3.6.1.4.1.311.20.2" },
                { "Certificate Trust List", "1.3.6.1.4.1.311.10.1" },
                { "Certification Authority Issuer", "1.3.6.1.5.5.7.48.2" },
                { "Certification Repository", "1.3.6.1.5.5.7.48.5" },
                { "Challenge Password", "1.2.840.113549.1.9.7" },
                { "Client Authentication", "1.3.6.1.5.5.7.3.2" },
                { "Client Information", "1.3.6.1.4.1.311.21.20" },
                { "CMC Attributes", "1.3.6.1.4.1.311.10.10.1" },
                { "CMC Data", "1.3.6.1.5.5.7.12.2" },
                { "CMC Extensions", "1.3.6.1.5.5.7.7.8" },
                { "CMC Response", "1.3.6.1.5.5.7.12.3" },
                { "CMC Status Info", "1.3.6.1.5.5.7.7.1" },
                { "CMS3DESwrap", "1.2.840.113549.1.9.16.3.6" },
                { "CMSRC2wrap", "1.2.840.113549.1.9.16.3.7" },
                { "CN", "2.5.4.3" },
                { "Code Signing", "1.3.6.1.5.5.7.3.3" },
                { "Confirm Certificate Acceptance", "1.3.6.1.5.5.7.7.24" },
                { "Content Type", "1.2.840.113549.1.9.3" },
                { "Counter Sign", "1.2.840.113549.1.9.6" },
                { "CPS", "1.3.6.1.5.5.7.2.1" },
                { "CRL Distribution Points", "2.5.29.31" },
                { "CRL Number", "2.5.29.20" },
                { "CRL Reason Code", "2.5.29.21" },
                { "Cross CA Version", "1.3.6.1.4.1.311.21.22" },
                { "Cross-Certificate Distribution Points", "1.3.6.1.4.1.311.10.9.1" },
                { "CTL Usage", "1.3.6.1.4.1.311.20.1" },
                { "DC", "0.9.2342.19200300.100.1.25" },
                { "Delta CRL Indicator", "2.5.29.27" },
                { "des", "1.3.14.3.2.7" },
                { "Description", "2.5.4.13" },
                { "DH", "1.2.840.10046.2.1" },
                { "Digital Rights", "1.3.6.1.4.1.311.10.5.1" },
                { "Directory Service Email Replication", "1.3.6.1.4.1.311.21.19" },
                { "dnQualifier", "2.5.4.46" },
                { "Document Signing", "1.3.6.1.4.1.311.10.3.12" },
                { "DS Object Guid", "1.3.6.1.4.1.311.25.1" },
                { "DSA", "1.2.840.10040.4.1" },
                { "dsaSHA1", "1.3.14.3.2.27" },
                { "Dummy Signer", "1.3.6.1.4.1.311.21.9" },
                { "E", "1.2.840.113549.1.9.1" },
                { "ec192wapi", "1.2.156.11235.1.1.2.1" },
                { "ECC", "1.2.840.10045.2.1" },
                { "ECDH_STD_SHA1_KDF", "1.3.133.16.840.63.0.2" },
                { "ECDH_STD_SHA256_KDF", "1.3.132.1.11.1" },
                { "ECDH_STD_SHA384_KDF", "1.3.132.1.11.2" },
                { "ECDSA_P256", "1.2.840.10045.3.1.7" },
                { "ECDSA_P384", "1.3.132.0.34" },
                { "ECDSA_P521", "1.3.132.0.35" },
                { "Embedded Windows System Component Verification", "1.3.6.1.4.1.311.10.3.8" },
                { "Encrypted Private Key", "1.3.6.1.4.1.311.21.13" },
                { "Encrypting File System", "1.3.6.1.4.1.311.10.3.4" },
                { "Enforce Certificate Chain Policy", "1.3.6.1.4.1.311.21.15" },
                { "Enhanced Key Usage", "2.5.29.37" },
                { "Enrollment CSP", "1.3.6.1.4.1.311.13.2.2" },
                { "Enrollment Name Value Pair", "1.3.6.1.4.1.311.13.2.1" },
                { "Enterprise Root OID", "1.3.6.1.4.1.311.21.8" },
                { "ESDH", "1.2.840.113549.1.9.16.3.5" },
                { "European Qualified Certificate", "0.4.0.1862.1.1" },
                { "File Recovery", "1.3.6.1.4.1.311.10.3.4.1" },
                { "Freshest CRL", "2.5.29.46" },
                { "G", "2.5.4.42" },
                { "Get Certificate", "1.3.6.1.5.5.7.7.15" },
                { "Get CRL", "1.3.6.1.5.5.7.7.16" },
                { "I", "2.5.4.43" },
                { "Inhibit Any Policy", "2.5.29.54" },
                { "IP security end system", "1.3.6.1.5.5.7.3.5" },
                { "IP security IKE intermediate", "1.3.6.1.5.5.8.2.2" },
                { "IP security tunnel termination", "1.3.6.1.5.5.7.3.6" },
                { "IP security user", "1.3.6.1.5.5.7.3.7" },
                { "Issuer Alternative Name", "2.5.29.18" },
                { "Issuing Distribution Point", "2.5.29.28" },
                { "Jurisdiction Hash", "2.16.840.1.113733.1.6.11" },
                { "KDC Authentication", "1.3.6.1.5.2.3.5" },
                { "Kernel Mode Code Signing", "1.3.6.1.4.1.311.61.1.1" },
                { "Key Attributes", "2.5.29.2" },
                { "Key Pack Licenses", "1.3.6.1.4.1.311.10.6.1" },
                { "Key Recovery", "1.3.6.1.4.1.311.10.3.11" },
                { "Key Recovery Agent", "1.3.6.1.4.1.311.21.6" },
                { "Key Usage", "2.5.29.15" },
                { "Key Usage Restriction", "2.5.29.4" },
                { "L", "2.5.4.7" },
                { "License Server Verification", "1.3.6.1.4.1.311.10.6.2" },
                { "Lifetime Signing", "1.3.6.1.4.1.311.10.3.13" },
                { "Logotype", "1.3.6.1.5.5.7.1.12" },
                { "md2", "1.2.840.113549.2.2" },
                { "md2RSA", "1.2.840.113549.1.1.2" },
                { "md4", "1.2.840.113549.2.4" },
                { "md4RSA", "1.2.840.113549.1.1.3" },
                { "md5", "1.2.840.113549.2.5" },
                { "md5RSA", "1.2.840.113549.1.1.4" },
                { "Message Digest", "1.2.840.113549.1.9.4" },
                { "mgf1", "1.2.840.113549.1.1.8" },
                { "Microsoft Time Stamping", "1.3.6.1.4.1.311.10.3.2" },
                { "Microsoft Trust List Signing", "1.3.6.1.4.1.311.10.3.1" },
                { "mosaicKMandUpdSig", "2.16.840.1.101.2.1.1.20" },
                { "mosaicUpdatedSig", "2.16.840.1.101.2.1.1.19" },
                { "Name Constraints", "2.5.29.30" },
                { "Netscape Base URL", "2.16.840.1.113730.1.2" },
                { "Netscape CA Policy URL", "2.16.840.1.113730.1.8" },
                { "Netscape CA Revocation URL", "2.16.840.1.113730.1.4" },
                { "Netscape Cert Renewal URL", "2.16.840.1.113730.1.7" },
                { "Netscape Cert Type", "2.16.840.1.113730.1.1" },
                { "Netscape Comment", "2.16.840.1.113730.1.13" },
                { "Netscape Revocation URL", "2.16.840.1.113730.1.3" },
                { "Netscape SSL ServerName", "2.16.840.1.113730.1.12" },
                { "Next CRL Publish", "1.3.6.1.4.1.311.21.4" },
                { "Next Update Location", "1.3.6.1.4.1.311.10.2" },
                { "nistP192", "1.2.840.10045.3.1.1" },
                { "nistP224", "1.3.132.0.33" },
                { "NO_SIGN", "1.3.6.1.5.5.7.6.2" },
                { "O", "2.5.4.10" },
                { "OCSP No Revocation Checking", "1.3.6.1.5.5.7.48.1.5" },
                { "OCSP Signing", "1.3.6.1.5.5.7.3.9" },
                { "OEM Windows System Component Verification", "1.3.6.1.4.1.311.10.3.7" },
                { "On-line Certificate Status Protocol", "1.3.6.1.5.5.7.48.1" },
                { "OS Version", "1.3.6.1.4.1.311.13.2.3" },
                { "OU", "2.5.4.11" },
                { "Phone", "2.5.4.20" },
                { "PKCS 7 Data", "1.2.840.113549.1.7.1" },
                { "PKCS 7 Digested", "1.2.840.113549.1.7.5" },
                { "PKCS 7 Encrypted", "1.2.840.113549.1.7.6" },
                { "PKCS 7 Enveloped", "1.2.840.113549.1.7.3" },
                { "PKCS 7 Signed", "1.2.840.113549.1.7.2" },
                { "PKCS 7 Signed Enveloped", "1.2.840.113549.1.7.4" },
                { "POBox", "2.5.4.18" },
                { "Policy Constraints", "2.5.29.36" },
                { "Policy Mappings", "2.5.29.33" },
                { "PostalCode", "2.5.4.17" },
                { "Prefer Signed Data", "1.2.840.113549.1.9.15.1" },
                { "Previous CA Certificate Hash", "1.3.6.1.4.1.311.21.2" },
                { "Principal Name", "1.3.6.1.4.1.311.20.2.3" },
                { "Private Key Archival", "1.3.6.1.4.1.311.21.5" },
                { "Private Key Usage Period", "2.5.29.16" },
                { "Published CRL Locations", "1.3.6.1.4.1.311.21.14" },
                { "Qualified Certificate Statements", "1.3.6.1.5.5.7.1.3" },
                { "Qualified Subordination", "1.3.6.1.4.1.311.10.3.10" },
                { "Query Pending", "1.3.6.1.5.5.7.7.21" },
                { "rc2", "1.2.840.113549.3.2" },
                { "rc4", "1.2.840.113549.3.4" },
                { "Recipient Nonce", "1.3.6.1.5.5.7.7.7" },
                { "Reg Info", "1.3.6.1.5.5.7.7.18" },
                { "Revoke Request", "1.3.6.1.5.5.7.7.17" },
                { "Root List Signer", "1.3.6.1.4.1.311.10.3.9" },
                { "Root Program Flags", "1.3.6.1.4.1.311.60.1.1" },
                { "RSA", "1.2.840.113549.1.1.1" },
                { "RSAES_OAEP", "1.2.840.113549.1.1.7" },
                { "RSASSA-PSS", "1.2.840.113549.1.1.10" },
                { "S", "2.5.4.8" },
                { "secP160k1", "1.3.132.0.9" },
                { "secP160r1", "1.3.132.0.8" },
                { "secP160r2", "1.3.132.0.30" },
                { "secP192k1", "1.3.132.0.31" },
                { "secP224k1", "1.3.132.0.32" },
                { "secP256k1", "1.3.132.0.10" },
                { "Secure Email", "1.3.6.1.5.5.7.3.4" },
                { "Secure Signature Creation Device Qualified Certificate", "0.4.0.1862.1.4" },
                { "Sender Nonce", "1.3.6.1.5.5.7.7.6" },
                { "Serialized Signature Serial Number", "1.3.6.1.4.1.311.10.3.3.1" },
                { "SERIALNUMBER", "2.5.4.5" },
                { "Server Authentication", "1.3.6.1.5.5.7.3.1" },
                { "sha1", "1.3.14.3.2.26" },
                { "sha1DSA", "1.2.840.10040.4.3" },
                { "sha1ECDSA", "1.2.840.10045.4.1" },
                { "sha1RSA", "1.2.840.113549.1.1.5" },
                { "sha256", "2.16.840.1.101.3.4.2.1" },
                { "sha256ECDSA", "1.2.840.10045.4.3.2" },
                { "sha256RSA", "1.2.840.113549.1.1.11" },
                { "sha384", "2.16.840.1.101.3.4.2.2" },
                { "sha384ECDSA", "1.2.840.10045.4.3.3" },
                { "sha384RSA", "1.2.840.113549.1.1.12" },
                { "sha512", "2.16.840.1.101.3.4.2.3" },
                { "sha512ECDSA", "1.2.840.10045.4.3.4" },
                { "sha512RSA", "1.2.840.113549.1.1.13" },
                { "Signing Time", "1.2.840.113549.1.9.5" },
                { "Smart Card Logon", "1.3.6.1.4.1.311.20.2.2" },
                { "SMIME Capabilities", "1.2.840.113549.1.9.15" },
                { "SN", "2.5.4.4" },
                { "specifiedECDSA", "1.2.840.10045.4.3" },
                { "STREET", "2.5.4.9" },
                { "Subject Alternative Name", "2.5.29.17" },
                { "Subject Directory Attributes", "2.5.29.9" },
                { "Subject Information Access", "1.3.6.1.5.5.7.1.11" },
                { "Subject Key Identifier", "2.5.29.14" },
                { "T", "2.5.4.12" },
                { "Time Stamping", "1.3.6.1.5.5.7.3.8" },
                { "Transaction Id", "1.3.6.1.5.5.7.7.5" },
                { "Unsigned CMC Request", "1.3.6.1.5.5.7.7" },
                { "Unstructured Address", "1.2.840.113549.1.9.8" },
                { "Unstructured Name", "1.2.840.113549.1.9.2" },
                { "User Notice", "1.3.6.1.5.5.7.2.2" },
                { "Virtual Base CRL Number", "1.3.6.1.4.1.311.21.3" },
                { "Windows Hardware Driver Verification", "1.3.6.1.4.1.311.10.3.5" },
                { "Windows Product Update", "1.3.6.1.4.1.311.31.1" },
                { "Windows System Component Verification", "1.3.6.1.4.1.311.10.3.6" },
                { "wtls9", "2.23.43.1.4.9" },
                { "X21Address", "2.5.4.24" },
                { "x962P192v2", "1.2.840.10045.3.1.2" },
                { "x962P192v3", "1.2.840.10045.3.1.3" },
                { "x962P239v1", "1.2.840.10045.3.1.4" },
                { "x962P239v2", "1.2.840.10045.3.1.5" },
                { "x962P239v3", "1.2.840.10045.3.1.6" },
                { "Yes or No Trust", "1.3.6.1.4.1.311.10.4.1" },
            };

        private static readonly Dictionary<string, string> s_oidToFriendlyName =
            s_friendlyNameToOid.ToDictionary(kvp => kvp.Value, kvp => kvp.Key);

        private static readonly Dictionary<string, string> s_compatOids =
            new Dictionary<string, string>
            {
                { "1.2.840.113549.1.3.1", "DH" },
                { "1.2.840.113549.1.9.14", "Certificate Extensions" },
                { "1.3.14.3.2.12", "DSA" },
                { "1.3.14.3.2.13", "sha1DSA" },
                { "1.3.14.3.2.15", "shaRSA" },
                { "1.3.14.3.2.18", "sha" },
                { "1.3.14.3.2.2", "md4RSA" },
                { "1.3.14.3.2.22", "RSA_KEYX" },
                { "1.3.14.3.2.29", "sha1RSA" },
                { "1.3.14.3.2.3", "md5RSA" },
                { "1.3.14.3.2.4", "md4RSA" },
                { "1.3.14.7.2.3.1", "md2RSA" },
                { "2.5.29.1", "Authority Key Identifier" },
                { "2.5.29.10", "Basic Constraints" },
                { "2.5.29.5", "Policy Mappings" },
                { "2.5.29.7", "Subject Alternative Name" },
                { "2.5.29.8", "Issuer Alternative Name" },
            };
    }
}
