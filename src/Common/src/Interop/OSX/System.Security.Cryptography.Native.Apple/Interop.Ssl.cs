// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using SafeSslHandle = System.Net.SafeSslHandle;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        // Read data from connection (or an instance delegate captured context) and write it to data
        // dataLength comes in as the capacity of data, goes out as bytes written.
        // Note: the true type of dataLength is `size_t*`, but on macOS that's most equal to `void**`
        internal unsafe delegate int SSLReadFunc(void* connection, byte* data, void** dataLength);

        // (In the C decl for this function data is "const byte*", justifying the second type).
        // Read *dataLength from data and write it to connection (or an instance delegate captured context),
        // and set *dataLength to the number of bytes actually transferred.
        internal unsafe delegate int SSLWriteFunc(void* connection, byte* data, void** dataLength);

        internal enum PAL_TlsProtocolId
        {
            Unknown = 0,
            Tls10 = 4,                /* TLS 1.0 */
            Tls11 = 7,                /* TLS 1.1 */
            Tls12 = 8,                /* TLS 1.2 */
        }

        internal enum PAL_TlsHandshakeState
        {
            Unknown,
            Complete,
            WouldBlock,
            ServerAuthCompleted,
            ClientAuthCompleted,
        }

        internal enum PAL_TlsIo
        {
            Unknown,
            Success,
            WouldBlock,
            ClosedGracefully,
        }

        [DllImport(Interop.Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SslCreateContext")]
        internal static extern System.Net.SafeSslHandle SslCreateContext(int isServer);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetMinProtocolVersion(
            SafeSslHandle sslHandle,
            PAL_TlsProtocolId minProtocolId);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetMaxProtocolVersion(
            SafeSslHandle sslHandle,
            PAL_TlsProtocolId maxProtocolId);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslCopyCertChain(
            SafeSslHandle sslHandle,
            out SafeX509ChainHandle pTrustOut,
            out int pOSStatus);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslCopyCADistinguishedNames(
            SafeSslHandle sslHandle,
            out SafeCFArrayHandle pArrayOut,
            out int pOSStatus);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetBreakOnServerAuth(
            SafeSslHandle sslHandle,
            int setBreak,
            out int pOSStatus);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetBreakOnClientAuth(
            SafeSslHandle sslHandle,
            int setBreak,
            out int pOSStatus);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetCertificate(
            SafeSslHandle sslHandle,
            SafeCreateHandle cfCertRefs);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslSetTargetName(
            SafeSslHandle sslHandle,
            string targetName,
            int cbTargetName,
            out int osStatus);

        [DllImport(Interop.Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SslHandshake")]
        internal static extern PAL_TlsHandshakeState SslHandshake(SafeSslHandle sslHandle);

        [DllImport(Interop.Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SslSetIoCallbacks")]
        internal static extern int SslSetIoCallbacks(
            SafeSslHandle sslHandle,
            SSLReadFunc readCallback,
            SSLWriteFunc writeCallback);

        [DllImport(Interop.Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SslWrite")]
        internal static extern unsafe PAL_TlsIo SslWrite(SafeSslHandle sslHandle, byte* writeFrom, int count, out int bytesWritten);

        [DllImport(Interop.Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_SslRead")]
        internal static extern unsafe PAL_TlsIo SslRead(SafeSslHandle sslHandle, byte* writeFrom, int count, out int bytesWritten);

        [DllImport(Interop.Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SslIsHostnameMatch(SafeSslHandle handle, SafeCreateHandle cfHostname);

        internal static void SslSetMinProtocolVersion(SafeSslHandle sslHandle, PAL_TlsProtocolId minProtocolId)
        {
            int osStatus = AppleCryptoNative_SslSetMinProtocolVersion(sslHandle, minProtocolId);

            if (osStatus != 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }
        }

        internal static void SslSetMaxProtocolVersion(SafeSslHandle sslHandle, PAL_TlsProtocolId maxProtocolId)
        {
            int osStatus = AppleCryptoNative_SslSetMaxProtocolVersion(sslHandle, maxProtocolId);

            if (osStatus != 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }
        }

        internal static SafeX509ChainHandle SslCopyCertChain(SafeSslHandle sslHandle)
        {
            SafeX509ChainHandle chainHandle;
            int osStatus;
            int result = AppleCryptoNative_SslCopyCertChain(sslHandle, out chainHandle, out osStatus);

            if (result == 1)
            {
                return chainHandle;
            }

            chainHandle.Dispose();

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_SslCopyCertChain returned {result}");
            throw new SslException();
        }

        internal static SafeCFArrayHandle SslCopyCADistinguishedNames(SafeSslHandle sslHandle)
        {
            SafeCFArrayHandle dnArray;
            int osStatus;
            int result = AppleCryptoNative_SslCopyCADistinguishedNames(sslHandle, out dnArray, out osStatus);

            if (result == 1)
            {
                return dnArray;
            }

            dnArray.Dispose();

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_SslCopyCADistinguishedNames returned {result}");
            throw new SslException();
        }

        internal static void SslBreakOnServerAuth(SafeSslHandle sslHandle, bool setBreak)
        {
            int osStatus;
            int result = AppleCryptoNative_SslSetBreakOnServerAuth(sslHandle, setBreak ? 1 : 0, out osStatus);

            if (result == 1)
            {
                return;
            }

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_SslSetBreakOnServerAuth returned {result}");
            throw new SslException();
        }

        internal static void SslBreakOnClientAuth(SafeSslHandle sslHandle, bool setBreak)
        {
            int osStatus;
            int result = AppleCryptoNative_SslSetBreakOnClientAuth(sslHandle, setBreak ? 1 : 0, out osStatus);

            if (result == 1)
            {
                return;
            }

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_SslSetBreakOnClientAuth returned {result}");
            throw new SslException();
        }

        internal static void SslSetCertificate(SafeSslHandle sslHandle, IntPtr[] certChainPtrs)
        {

            using (SafeCreateHandle cfCertRefs = CoreFoundation.CFArrayCreate(certChainPtrs, certChainPtrs.Length))
            {
                int osStatus = AppleCryptoNative_SslSetCertificate(sslHandle, cfCertRefs);

                if (osStatus != 0)
                {
                    throw CreateExceptionForOSStatus(osStatus);
                }
            }
        }

        internal static void SslSetTargetName(SafeSslHandle sslHandle, string targetName)
        {
            Debug.Assert(!string.IsNullOrEmpty(targetName));

            int osStatus;
            int cbTargetName = System.Text.Encoding.UTF8.GetByteCount(targetName);

            int result = AppleCryptoNative_SslSetTargetName(sslHandle, targetName, cbTargetName, out osStatus);

            if (result == 1)
            {
                return;
            }

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            Debug.Fail($"AppleCryptoNative_SslSetTargetName returned {result}");
            throw new SslException();
        }

        public static bool SslCheckHostnameMatch(SafeSslHandle handle, string hostName)
        {
            int result;
            // The IdnMapping converts Unicode input into the IDNA punycode sequence.
            // It also does host case normalization.  The bypass logic would be something
            // like "all characters being within [a-z0-9.-]+"
            // Since it's not documented as being thread safe, create a new one each time.
            //
            // The SSL Policy (SecPolicyCreateSSL) has been verified as not inherently supporting
            // IDNA as of macOS 10.12.1 (Sierra).  If it supports low-level IDNA at a later date,
            // this code could be removed.
            //
            // It was verified as supporting case invariant match as of 10.12.1 (Sierra).
            string matchName = new System.Globalization.IdnMapping().GetAscii(hostName);

            using (SafeCreateHandle cfHostname = CoreFoundation.CFStringCreateWithCString(matchName))
            {
                result = AppleCryptoNative_SslIsHostnameMatch(handle, cfHostname);
            }

            switch (result)
            {
                case 0:
                    return false;
                case 1:
                    return true;
                default:
                    Debug.Fail($"AppleCryptoNative_SslIsHostnameMatch returned {result}");
                    throw new SslException();
            }
        }
    }
}

namespace System.Net
{
    internal sealed class SafeSslHandle : SafeHandle
    {
        internal SafeSslHandle()
            : base(IntPtr.Zero, ownsHandle: true)
        {
        }

        internal SafeSslHandle(IntPtr invalidHandleValue, bool ownsHandle)
            : base(invalidHandleValue, ownsHandle)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.CoreFoundation.CFRelease(handle);
            SetHandle(IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}