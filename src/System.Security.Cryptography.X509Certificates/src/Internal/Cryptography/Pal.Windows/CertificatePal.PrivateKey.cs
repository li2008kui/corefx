// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

using Internal.Cryptography.Pal.Native;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class CertificatePal : IDisposable, ICertificatePal
    {
        public bool HasPrivateKey
        {
            get
            {
                return _certContext.ContainsPrivateKey;
            }
        }

        public RSA GetRSAPrivateKey()
        {
            return GetPrivateKey<RSA>(
                delegate (CspParameters csp)
                {
#if uap
                    // In .NET Native (UWP) we don't have access to CAPI, so it's CNG-or-nothing.
                    // But we don't expect to get here, so it shouldn't be a problem.
    
                    Debug.Fail("A CAPI provider type code was specified");
                    return null;
#else
                    return new RSACryptoServiceProvider(csp);
#endif
                },
                delegate (CngKey cngKey)
                {
                    return new RSACng(cngKey);
                }
            );
        }

        public DSA GetDSAPrivateKey()
        {
            return GetPrivateKey<DSA>(
                delegate (CspParameters csp)
                {
#if uap
                    // In .NET Native (UWP) we don't have access to CAPI, so it's CNG-or-nothing.
                    // But we don't expect to get here, so it shouldn't be a problem.
    
                    Debug.Fail("A CAPI provider type code was specified");
                    return null;
#else
                    return new DSACryptoServiceProvider(csp);
#endif
                },
                delegate (CngKey cngKey)
                {
                    return new DSACng(cngKey);
                }
            );
        }

        public ECDsa GetECDsaPrivateKey()
        {
            return GetPrivateKey<ECDsa>(
                delegate (CspParameters csp)
                {
                    throw new NotSupportedException(SR.NotSupported_ECDsa_Csp);
                },
                delegate (CngKey cngKey)
                {
                    return new ECDsaCng(cngKey);
                }
            );
        }

        public ICertificatePal CreateCopyWithPrivateKey(DSA dsa)
        {
            DSACng dsaCng = dsa as DSACng;
            ICertificatePal clone = null;

            if (dsaCng != null)
            {
                clone = CloneWithPersistedCngKey(dsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            DSACryptoServiceProvider dsaCsp = dsa as DSACryptoServiceProvider;

            if (dsaCsp != null)
            {
                clone = CloneWithPersistedCapiKey(dsaCsp.CspKeyContainerInfo);

                if (clone != null)
                {
                    return clone;
                }
            }

            DSAParameters privateParameters = dsa.ExportParameters(true);

            using (DSACng clonedKey = new DSACng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CloneWithEphemeralKey(clonedKey.Key);
            }
        }

        public ICertificatePal CreateCopyWithPrivateKey(ECDsa ecdsa)
        {
            ECDsaCng ecdsaCng = ecdsa as ECDsaCng;

            if (ecdsaCng != null)
            {
                ICertificatePal clone = CloneWithPersistedCngKey(ecdsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            ECParameters privateParameters = ecdsa.ExportParameters(true);

            using (ECDsaCng clonedKey = new ECDsaCng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CloneWithEphemeralKey(clonedKey.Key);
            }
        }

        public ICertificatePal CreateCopyWithPrivateKey(RSA rsa)
        {
            RSACng rsaCng = rsa as RSACng;
            ICertificatePal clone = null;

            if (rsaCng != null)
            {
                clone = CloneWithPersistedCngKey(rsaCng.Key);

                if (clone != null)
                {
                    return clone;
                }
            }

            RSACryptoServiceProvider rsaCsp = rsa as RSACryptoServiceProvider;

            if (rsaCsp != null)
            {
                clone = CloneWithPersistedCapiKey(rsaCsp.CspKeyContainerInfo);

                if (clone != null)
                {
                    return clone;
                }
            }

            RSAParameters privateParameters = rsa.ExportParameters(true);

            using (RSACng clonedKey = new RSACng())
            {
                clonedKey.ImportParameters(privateParameters);

                return CloneWithEphemeralKey(clonedKey.Key);
            }
        }

        private T GetPrivateKey<T>(Func<CspParameters, T> createCsp, Func<CngKey, T> createCng) where T : AsymmetricAlgorithm
        {
            CngKeyHandleOpenOptions cngHandleOptions;
            SafeNCryptKeyHandle ncryptKey = TryAcquireCngPrivateKey(CertContext, out cngHandleOptions);
            if (ncryptKey != null)
            {
                CngKey cngKey = CngKey.Open(ncryptKey, cngHandleOptions);
                return createCng(cngKey);
            }
 
            CspParameters cspParameters = GetPrivateKeyCsp();
            if (cspParameters == null)
                return null;

            if (cspParameters.ProviderType == 0)
            {
                // ProviderType being 0 signifies that this is actually a CNG key, not a CAPI key. Crypt32.dll stuffs the CNG Key Storage Provider
                // name into CRYPT_KEY_PROV_INFO->ProviderName, and the CNG key name into CRYPT_KEY_PROV_INFO->KeyContainerName.

                string keyStorageProvider = cspParameters.ProviderName;
                string keyName = cspParameters.KeyContainerName;
                CngKey cngKey = CngKey.Open(keyName, new CngProvider(keyStorageProvider));
                return createCng(cngKey);
            }
            else
            {
                // ProviderType being non-zero signifies that this is a CAPI key.
#if uap
                // In .NET Native (UWP) we don't have access to CAPI, so it's CNG-or-nothing.
                // But we don't expect to get here, so it shouldn't be a problem.
    
                Debug.Fail("A CAPI provider type code was specified");
                return null;
#else
                // We never want to stomp over certificate private keys.
                cspParameters.Flags |= CspProviderFlags.UseExistingKey;
                return createCsp(cspParameters);
#endif
            }
        }

        private static SafeNCryptKeyHandle TryAcquireCngPrivateKey(
            SafeCertContextHandle certificateContext,
            out CngKeyHandleOpenOptions handleOptions)
        {
            Debug.Assert(certificateContext != null, "certificateContext != null");
            Debug.Assert(!certificateContext.IsClosed && !certificateContext.IsInvalid,
                         "!certificateContext.IsClosed && !certificateContext.IsInvalid");

            IntPtr privateKeyPtr;

            // If the certificate has a key handle instead of a key prov info, return the
            // ephemeral key
            {
                int cbData = IntPtr.Size;

                if (Interop.crypt32.CertGetCertificateContextProperty(
                    certificateContext,
                    CertContextPropId.CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                    out privateKeyPtr,
                    ref cbData))
                {
                    handleOptions = CngKeyHandleOpenOptions.EphemeralKey;
                    return new SafeNCryptKeyHandle(privateKeyPtr, certificateContext);
                }
            }

            bool freeKey = true;
            SafeNCryptKeyHandle privateKey = null;
            handleOptions = CngKeyHandleOpenOptions.None;
            try
            {
                int keySpec = 0;
                if (!Interop.crypt32.CryptAcquireCertificatePrivateKey(
                    certificateContext,
                    CryptAcquireFlags.CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
                    IntPtr.Zero,
                    out privateKey,
                    out keySpec,
                    out freeKey))
                {
                    int dwErrorCode = Marshal.GetLastWin32Error();

                    // The documentation for CryptAcquireCertificatePrivateKey says that freeKey
                    // should already be false if "key acquisition fails", and it can be presumed
                    // that privateKey was set to 0.  But, just in case:
                    freeKey = false;
                    privateKey?.SetHandleAsInvalid();
                    return null;
                }

                // It is very unlikely that Windows will tell us !freeKey other than when reporting failure,
                // because we set neither CRYPT_ACQUIRE_CACHE_FLAG nor CRYPT_ACQUIRE_USE_PROV_INFO_FLAG, which are
                // currently the only two success situations documented. However, any !freeKey response means the
                // key's lifetime is tied to that of the certificate, so re-register the handle as a child handle
                // of the certificate.
                if (!freeKey && privateKey != null && !privateKey.IsInvalid)
                {
                    var newKeyHandle = new SafeNCryptKeyHandle(privateKey.DangerousGetHandle(), certificateContext);
                    privateKey.SetHandleAsInvalid();
                    privateKey = newKeyHandle;
                    freeKey = true;
                }

                return privateKey;
            }
            catch
            {
                // If we aren't supposed to free the key, and we're not returning it,
                // just tell the SafeHandle to not free itself.
                if (privateKey != null && !freeKey)
                {
                    privateKey.SetHandleAsInvalid();
                }

                throw;
            }
        }

        //
        // Returns the private key referenced by a store certificate. Note that despite the return type being declared "CspParameters",
        // the key can actually be a CNG key. To distinguish, examine the ProviderType property. If it is 0, this key is a CNG key with
        // the various properties of CspParameters being "repurposed" into storing CNG info. 
        // 
        // This is a behavior this method inherits directly from the Crypt32 CRYPT_KEY_PROV_INFO semantics.
        //
        // It would have been nice not to let this ugliness escape out of this helper method. But X509Certificate2.ToString() calls this 
        // method too so we cannot just change it without breaking its output.
        // 
        private CspParameters GetPrivateKeyCsp()
        {
            int cbData = 0;
            if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cbData))
            {
                int dwErrorCode = Marshal.GetLastWin32Error();
                if (dwErrorCode == ErrorCode.CRYPT_E_NOT_FOUND)
                    return null;
                throw dwErrorCode.ToCryptographicException();
            }

            unsafe
            {
                byte[] privateKey = new byte[cbData];
                fixed (byte* pPrivateKey = privateKey)
                {
                    if (!Interop.crypt32.CertGetCertificateContextProperty(_certContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, privateKey, ref cbData))
                        throw Marshal.GetLastWin32Error().ToCryptographicException();
                    CRYPT_KEY_PROV_INFO* pKeyProvInfo = (CRYPT_KEY_PROV_INFO*)pPrivateKey;

                    CspParameters cspParameters = new CspParameters();
                    cspParameters.ProviderName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszProvName));
                    cspParameters.KeyContainerName = Marshal.PtrToStringUni((IntPtr)(pKeyProvInfo->pwszContainerName));
                    cspParameters.ProviderType = pKeyProvInfo->dwProvType;
                    cspParameters.KeyNumber = pKeyProvInfo->dwKeySpec;
                    cspParameters.Flags = (CspProviderFlags)((pKeyProvInfo->dwFlags & CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) == CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET ? CspProviderFlags.UseMachineKeyStore : 0);
                    return cspParameters;
                }
            }
        }


        private unsafe ICertificatePal CloneWithPersistedCngKey(CngKey cngKey)
        {
            if (string.IsNullOrEmpty(cngKey.KeyName))
            {
                return null;
            }

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);

            // CAPI RSA_SIGN keys won't open correctly under CNG without the key number being specified, so
            // check to see if we can figure out what key number it needs to re-open.
            CngProvider provider = cngKey.Provider;
            string keyName = cngKey.KeyName;
            bool machineKey = cngKey.IsMachineKey;

            int keySpec = GuessKeySpec(provider, keyName, machineKey, cngKey.AlgorithmGroup);

            CRYPT_KEY_PROV_INFO keyProvInfo = new CRYPT_KEY_PROV_INFO();

            fixed (char* keyNamePtr = cngKey.KeyName)
            fixed (char* provNamePtr = cngKey.Provider.Provider)
            {
                keyProvInfo.pwszContainerName = keyNamePtr;
                keyProvInfo.pwszProvName = provNamePtr;
                keyProvInfo.dwFlags = machineKey ? CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET : 0;
                keyProvInfo.dwKeySpec = keySpec;

                if (!Interop.crypt32.CertSetCertificateContextProperty(
                    pal._certContext,
                    CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    pal.Dispose();
                    throw Marshal.GetLastWin32Error().ToCryptographicException();
                }
            }

            return pal;
        }

        private static int GuessKeySpec(
            CngProvider provider,
            string keyName,
            bool machineKey,
            CngAlgorithmGroup algorithmGroup)
        {
            if (provider == CngProvider.MicrosoftSoftwareKeyStorageProvider ||
                provider == CngProvider.MicrosoftSmartCardKeyStorageProvider)
            {
                // Well-known CNG providers, keySpec is 0.
                return 0;
            }


            const int NTE_BAD_KEYSET = unchecked((int)0x80090016);

            try
            {
                CngKeyOpenOptions options = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;

                using (CngKey.Open(keyName, provider, options))
                {
                    // It opened with keySpec 0, so use keySpec 0.
                    return 0;
                }
            }
            catch (CryptographicException e)
            {
                Debug.Assert(
                    e.HResult == NTE_BAD_KEYSET,
                    $"CngKey.Open had unexpected error: 0x{e.HResult:X8}: {e.Message}");

                CspParameters cspParameters = new CspParameters
                {
                    ProviderName = provider.Provider,
                    KeyContainerName = keyName,
                    Flags = CspProviderFlags.UseExistingKey,
                    KeyNumber = (int)KeyNumber.Signature,
                };

                if (machineKey)
                {
                    cspParameters.Flags |= CspProviderFlags.UseMachineKeyStore;
                }

                if (algorithmGroup == CngAlgorithmGroup.Rsa)
                {
                    // Try the AT_SIGNATURE spot in each of the 4 RSA provider type values,
                    // ideally one of them will work.
                    const int PROV_RSA_FULL = 1;
                    const int PROV_RSA_SIG = 2;
                    const int PROV_RSA_SCHANNEL = 12;
                    const int PROV_RSA_AES = 24;

                    // These are ordered in terms of perceived likeliness, given that the key
                    // is AT_SIGNATURE.
                    int[] provTypes =
                    {
                        PROV_RSA_FULL,
                        PROV_RSA_AES,
                        PROV_RSA_SCHANNEL,

                        // Nothing should be PROV_RSA_SIG, but if everything else has failed,
                        // just try this last thing.
                        PROV_RSA_SIG,
                    };

                    foreach (int provType in provTypes)
                    {
                        cspParameters.ProviderType = provType;

                        try
                        {
                            using (new RSACryptoServiceProvider(cspParameters))
                            {
                                return cspParameters.KeyNumber;
                            }
                        }
                        catch (CryptographicException)
                        {
                        }
                    }

                    Debug.Fail("RSA key did not open with KeyNumber 0 or AT_SIGNATURE");
                }
                else if (algorithmGroup == CngAlgorithmGroup.Dsa)
                {
                    const int PROV_DSS = 3;
                    const int PROV_DSS_DH = 13;

                    int[] provTypes =
                    {
                        PROV_DSS_DH,
                        PROV_DSS,
                    };

                    foreach (int provType in provTypes)
                    {
                        cspParameters.ProviderType = provType;

                        try
                        {
                            using (new DSACryptoServiceProvider(cspParameters))
                            {
                                return cspParameters.KeyNumber;
                            }
                        }
                        catch (CryptographicException)
                        {
                        }
                    }

                    Debug.Fail("DSA key did not open with KeyNumber 0 or AT_SIGNATURE");
                }

                throw;
            }
        }

        private unsafe ICertificatePal CloneWithPersistedCapiKey(CspKeyContainerInfo keyContainerInfo)
        {
            if (string.IsNullOrEmpty(keyContainerInfo.KeyContainerName))
            {
                return null;
            }

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);
            CRYPT_KEY_PROV_INFO keyProvInfo = new CRYPT_KEY_PROV_INFO();

            fixed (char* keyName = keyContainerInfo.KeyContainerName)
            fixed (char* provName = keyContainerInfo.ProviderName)
            {
                keyProvInfo.pwszContainerName = keyName;
                keyProvInfo.pwszProvName = provName;
                keyProvInfo.dwFlags = keyContainerInfo.MachineKeyStore ? CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET : 0;
                keyProvInfo.dwProvType = keyContainerInfo.ProviderType;
                keyProvInfo.dwKeySpec = (int)keyContainerInfo.KeyNumber;

                if (!Interop.crypt32.CertSetCertificateContextProperty(
                    pal._certContext,
                    CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID,
                    CertSetPropertyFlags.None,
                    &keyProvInfo))
                {
                    pal.Dispose();
                    throw Marshal.GetLastWin32Error().ToCryptographicException();
                }
            }

            return pal;
        }

        private unsafe ICertificatePal CloneWithEphemeralKey(CngKey cngKey)
        {
            Debug.Assert(string.IsNullOrEmpty(cngKey.KeyName));

            SafeNCryptKeyHandle handle = cngKey.Handle;

            // Make a new pal from bytes.
            CertificatePal pal = (CertificatePal)FromBlob(RawData, SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.PersistKeySet);

            if (!Interop.crypt32.CertSetCertificateContextProperty(
                pal._certContext,
                CertContextPropId.CERT_NCRYPT_KEY_HANDLE_PROP_ID,
                CertSetPropertyFlags.CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG,
                handle))
            {
                pal.Dispose();
                throw Marshal.GetLastWin32Error().ToCryptographicException();
            }

            // The value was transferred to the certificate.
            handle.SetHandleAsInvalid();
            return pal;
        }
    }
}
