// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed class SecTrustChainPal : IChainPal
    {
        private static readonly DateTime s_cfDateEpoch = new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private Stack<SafeHandle> _extraHandles;
        public SafeX509ChainHandle SafeHandle { get; private set; }
        public X509ChainElement[] ChainElements { get; private set; }
        public X509ChainStatus[] ChainStatus { get; private set; }
        private DateTime _verificationTime;

        internal SecTrustChainPal()
        {
            _extraHandles = new Stack<SafeHandle>();
        }

        internal void OpenTrustHandle(
            ICertificatePal leafCert,
            X509Certificate2Collection extraStore,
            bool checkRevocation)
        {
            SafeCreateHandle policiesArray = PreparePoliciesArray(checkRevocation);
            SafeCreateHandle certsArray = PrepareCertsArray(leafCert, extraStore);

            int osStatus;

            SafeX509ChainHandle chain;
            int ret = Interop.AppleCrypto.AppleCryptoNative_X509ChainCreate(
                certsArray,
                policiesArray,
                out chain,
                out osStatus);

            if (ret == 1)
            {
                SafeHandle = chain;
                return;
            }

            chain.Dispose();

            if (ret == 0)
            {
                throw Interop.AppleCrypto.CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_X509ChainCreate returned unexpected return value {ret}");
            throw new CryptographicException();
        }

        public void Dispose()
        {
            if (_extraHandles == null)
                return;

            Stack<SafeHandle> extraHandles = _extraHandles;
            _extraHandles = null;

            SafeHandle?.Dispose();

            while (extraHandles.Count > 0)
            {
                extraHandles.Pop().Dispose();
            }
        }

        public bool? Verify(X509VerificationFlags flags, out Exception exception)
        {
            exception = null;

            return ChainVerifier.Verify(ChainElements, flags);
        }

        private SafeCreateHandle PreparePoliciesArray(bool checkRevocation)
        {
            IntPtr[] policies = new IntPtr[checkRevocation ? 2 : 1];

            SafeHandle defaultPolicy = Interop.AppleCrypto.X509ChainCreateDefaultPolicy();
            _extraHandles.Push(defaultPolicy);
            policies[0] = defaultPolicy.DangerousGetHandle();

            if (checkRevocation)
            {
                SafeHandle revPolicy = Interop.AppleCrypto.X509ChainCreateRevocationPolicy();
                _extraHandles.Push(revPolicy);
                policies[1] = revPolicy.DangerousGetHandle();
            }

            SafeCreateHandle policiesArray =
                Interop.CoreFoundation.CFArrayCreate(policies, policies.Length);

            _extraHandles.Push(policiesArray);
            return policiesArray;
        }

        private SafeCreateHandle PrepareCertsArray(ICertificatePal cert, X509Certificate2Collection extraStore)
        {
            IntPtr[] ptrs = new IntPtr[1 + (extraStore?.Count ?? 0)];

            AppleCertificatePal applePal = (AppleCertificatePal)cert;

            ptrs[0] = applePal.CertificateHandle.DangerousGetHandle();

            if (extraStore != null)
            {
                for (int i = 0; i < extraStore.Count; i++)
                {
                    AppleCertificatePal extraCertPal = (AppleCertificatePal)extraStore[i].Pal;

                    ptrs[i + 1] = extraCertPal.CertificateHandle.DangerousGetHandle();
                }
            }

            SafeCreateHandle certsArray = Interop.CoreFoundation.CFArrayCreate(ptrs, ptrs.Length);
            _extraHandles.Push(certsArray);
            return certsArray;
        }

        public void Execute(DateTime verificationTime, bool allowNetwork)
        {
            int osStatus;

            double epochDeltaSeconds = (verificationTime - s_cfDateEpoch).TotalSeconds;
            _verificationTime = verificationTime;

            int ret = Interop.AppleCrypto.AppleCryptoNative_X509ChainEvaluate(
                SafeHandle,
                epochDeltaSeconds,
                allowNetwork,
                out osStatus);

            if (ret == 0)
                throw Interop.AppleCrypto.CreateExceptionForOSStatus(osStatus);

            if (ret == 2)
                throw new NotImplementedException("Handle failure");

            if (ret != 1)
                throw new CryptographicUnexpectedOperationException($"ChainCreate: {ret}");

            ParseResults();
        }

        private void ParseResults()
        {
            long elementCount = Interop.AppleCrypto.X509ChainGetChainSize(SafeHandle);
            X509ChainElement[] elements = new X509ChainElement[elementCount];

            int allStatus = 0;

            using (var trustResults = Interop.AppleCrypto.X509ChainGetTrustResults(SafeHandle))
            {
                for (long elementIdx = 0; elementIdx < elementCount; elementIdx++)
                {
                    IntPtr certHandle =
                        Interop.AppleCrypto.X509ChainGetCertificateAtIndex(SafeHandle, elementIdx);

                    int dwStatus;
                    int ret = Interop.AppleCrypto.X509ChainGetStatusAtIndex(trustResults, elementIdx, out dwStatus);

                    // A return value of zero means no errors happened in locating the status (negative) or in
                    // parsing the status (positive).
                    if (ret != 0)
                    {
                        Debug.Fail($"X509ChainGetStatusAtIndex returned unexpected error {ret}");
                        throw new CryptographicException();
                    }

                    X509Certificate2 cert = new X509Certificate2(certHandle);

                    FixupStatus(cert, ref dwStatus);

                    allStatus |= dwStatus;
                    X509ChainElement element = BuildElement(cert, dwStatus);
                    elements[elementIdx] = element;
                }
            }

            ChainElements = elements;

            X509ChainElement rollupElement = BuildElement(null, allStatus);
            ChainStatus = rollupElement.ChainElementStatus;
        }

        private static void FixupStatus(X509Certificate2 cert, ref int dwStatus)
        {
            X509ChainStatusFlags flags = (X509ChainStatusFlags)dwStatus;

            if ((flags & X509ChainStatusFlags.UntrustedRoot) != 0)
            {
                X509ChainStatusFlags newFlag = FindUntrustedRootReason(cert);

                if (newFlag != X509ChainStatusFlags.UntrustedRoot)
                {
                    flags &= ~X509ChainStatusFlags.UntrustedRoot;
                    flags |= newFlag;

                    dwStatus = (int)flags;
                }
            }
        }

        private static X509ChainStatusFlags FindUntrustedRootReason(X509Certificate2 cert)
        {
            // UntrustedRoot comes back for at least the following reasons:
            // 1. The parent cert could not be found (no network, no AIA, etc) (PartialChain)
            // 2. The root cert was found, and wasn't trusted (UntrustedRoot)
            // 3. The certificate was tampered with, so the parent was declared invalid.
            //
            // In the #3 case we'd like to call it NotSignatureValid, but since we didn't get
            // the parent certificate we can't recompute that, so it'll just get called
            // PartialChain.
            if (!cert.SubjectName.RawData.ContentsEqual(cert.IssuerName.RawData))
            {
                return X509ChainStatusFlags.PartialChain;
            }

            // Okay, so we're looking at a self-signed certificate.
            // What are some situations?
            // 1. A private / new root certificate was matched which is not trusted (UntrustedRoot)
            // 2. A valid root certificate is tampered with (NotSignatureValid)
            // 3. A valid certificate is created which has the same subject name as
            //    an existing root cert (UntrustedRoot)
            //
            // To a user, case 2 and 3 aren't really distinguishable:
            // "What do you mean [my favorite CA] isn't trusted?".
            // NotSignatureValid would reveal the tamper, but since whoever was tampering can
            // easily re-sign a self-signed cert, it's not worth duplicating the signature
            // computation here.
            return X509ChainStatusFlags.UntrustedRoot;
        }

        private X509ChainElement BuildElement(X509Certificate2 cert, int dwStatus)
        {
            const int errSecCertificateExpired = -67818;
            const int errSecCertificateNotValidYet = -67819;

            if (dwStatus == 0)
            {
                return new X509ChainElement(cert, Array.Empty<X509ChainStatus>(), "");
            }

            List<X509ChainStatus> statuses = new List<X509ChainStatus>();
            X509ChainStatusFlags flags = (X509ChainStatusFlags)dwStatus;

            foreach (X509ChainErrorMapping mapping in X509ChainErrorMapping.s_chainErrorMappings)
            {
                if ((mapping.ChainStatusFlag & flags) == mapping.ChainStatusFlag)
                {
                    int osStatus;

                    // Disambiguate the NotTimeValid code to get the right string.
                    if (mapping.ChainStatusFlag == X509ChainStatusFlags.NotTimeValid)
                    {
                        if (cert != null && cert.NotBefore > _verificationTime)
                        {
                            osStatus = errSecCertificateNotValidYet;
                        }
                        else
                        {
                            osStatus = errSecCertificateExpired;
                        }
                    }
                    else
                    {
                        osStatus = mapping.OSStatus;
                    }

                    statuses.Add(
                        new X509ChainStatus
                        {
                            Status = mapping.ChainStatusFlag,
                            StatusInformation = Interop.AppleCrypto.GetSecErrorString(osStatus),
                        });
                }
            }

            return new X509ChainElement(cert, statuses.ToArray(), "");
        }

        private struct X509ChainErrorMapping
        {
            internal static readonly X509ChainErrorMapping[] s_chainErrorMappings =
            {
                new X509ChainErrorMapping(X509ChainStatusFlags.NotTimeValid),
                new X509ChainErrorMapping(X509ChainStatusFlags.NotTimeNested), 
                new X509ChainErrorMapping(X509ChainStatusFlags.Revoked), 
                new X509ChainErrorMapping(X509ChainStatusFlags.NotSignatureValid), 
                new X509ChainErrorMapping(X509ChainStatusFlags.NotValidForUsage), 
                new X509ChainErrorMapping(X509ChainStatusFlags.UntrustedRoot), 
                new X509ChainErrorMapping(X509ChainStatusFlags.RevocationStatusUnknown), 
                new X509ChainErrorMapping(X509ChainStatusFlags.Cyclic), 
                new X509ChainErrorMapping(X509ChainStatusFlags.InvalidExtension), 
                new X509ChainErrorMapping(X509ChainStatusFlags.InvalidPolicyConstraints), 
                new X509ChainErrorMapping(X509ChainStatusFlags.InvalidBasicConstraints), 
                new X509ChainErrorMapping(X509ChainStatusFlags.InvalidNameConstraints), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasNotSupportedNameConstraint), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasNotDefinedNameConstraint), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasNotPermittedNameConstraint), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasExcludedNameConstraint), 
                new X509ChainErrorMapping(X509ChainStatusFlags.PartialChain), 
                new X509ChainErrorMapping(X509ChainStatusFlags.CtlNotTimeValid), 
                new X509ChainErrorMapping(X509ChainStatusFlags.CtlNotSignatureValid), 
                new X509ChainErrorMapping(X509ChainStatusFlags.CtlNotValidForUsage), 
                new X509ChainErrorMapping(X509ChainStatusFlags.OfflineRevocation), 
                new X509ChainErrorMapping(X509ChainStatusFlags.NoIssuanceChainPolicy), 
                new X509ChainErrorMapping(X509ChainStatusFlags.ExplicitDistrust), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasNotSupportedCriticalExtension), 
                new X509ChainErrorMapping(X509ChainStatusFlags.HasWeakSignature), 
            };

            internal readonly X509ChainStatusFlags ChainStatusFlag;
            internal readonly int OSStatus;

            private X509ChainErrorMapping(X509ChainStatusFlags flag)
            {
                ChainStatusFlag = flag;
                OSStatus = Interop.AppleCrypto.GetOSStatusForChainStatus(flag);
            }
        }
    }

    internal sealed partial class ChainPal
    {
        public static IChainPal FromHandle(IntPtr chainContext)
        {
            // This is possible to do on Apple's platform, but is tricky in execution.
            // In Windows, CertGetCertificateChain is what allocates the handle, and it does
            // * Chain building
            // * Revocation checking as directed
            // But notably does not apply any policy rules (TLS hostname matching, etc), or
            // even inquire as to what policies should be applied.
            //
            // On Apple, the order is reversed.  Creating the SecTrust(Ref) object requires
            // the policy to match against, but when the handle is created it might not have
            // built the chain.  Then a call to SecTrustEvaluate actually does the chain building.
            //
            // This means that Windows never had to handle the "unevaluated chain" pointer, but
            // on Apple we would.  And so it means that the .NET API doesn't understand it can be in
            // that state.
            // * Is that an exception on querying the status or elements?
            // * An exception in this call chain (new X509Chain(IntPtr))?
            // * Should we build the chain on first data query?
            // * Should we build the chain now?
            //
            // The only thing that is known is that if this method succeeds it does not take ownership
            // of the handle.  So it should CFRetain the handle and let the PAL object's SafeHandle
            // still Dispose/CFRelease.
            //
            // For now, just PNSE, it didn't work when we used OpenSSL, and we can add this when we
            // decide what it should do.
            throw new PlatformNotSupportedException();
        }

        public static bool ReleaseSafeX509ChainHandle(IntPtr handle)
        {
            Interop.CoreFoundation.CFRelease(handle);
            return true;
        }

        public static IChainPal BuildChain(
            bool useMachineContext,
            ICertificatePal cert,
            X509Certificate2Collection extraStore,
            OidCollection applicationPolicy,
            OidCollection certificatePolicy,
            X509RevocationMode revocationMode,
            X509RevocationFlag revocationFlag,
            DateTime verificationTime,
            TimeSpan timeout)
        {
            //if (applicationPolicy != null && applicationPolicy.Count > 0)
            //    throw new PlatformNotSupportedException(nameof(applicationPolicy));
            //if (certificatePolicy != null && certificatePolicy.Count > 0)
            //    throw new PlatformNotSupportedException(nameof(certificatePolicy));

            if (verificationTime.Kind == DateTimeKind.Unspecified)
            {
                verificationTime = verificationTime.ToLocalTime();
            }

            verificationTime = verificationTime.ToUniversalTime();

            bool allowNetwork = revocationMode == X509RevocationMode.Online;
            bool checkRevocation = revocationMode != X509RevocationMode.NoCheck;

            SecTrustChainPal chainPal = new SecTrustChainPal();

            try
            {
                chainPal.OpenTrustHandle(cert, extraStore, checkRevocation);
                chainPal.Execute(verificationTime, allowNetwork);
            }
            catch
            {
                chainPal.Dispose();
                throw;
            }

            return chainPal;
        }
    }
}