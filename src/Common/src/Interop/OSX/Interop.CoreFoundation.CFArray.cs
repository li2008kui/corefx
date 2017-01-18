// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

// Declared as signed long, which has sizeof(void*) on OSX.
using CFIndex=System.IntPtr;

internal static partial class Interop
{
    internal static partial class CoreFoundation
    {
        [DllImport(Libraries.CoreFoundationLibrary, EntryPoint = "CFArrayGetCount")]
        private static extern CFIndex _CFArrayGetCount(SafeCFArrayHandle cfArray);

        [DllImport(Libraries.CoreFoundationLibrary, EntryPoint = "CFArrayGetValueAtIndex")]
        private static extern SafeCreateHandle CFArrayGetValueAtIndex(SafeCFArrayHandle cfArray, CFIndex index);

        internal static long CFArrayGetCount(SafeCFArrayHandle cfArray)
        {
            return _CFArrayGetCount(cfArray).ToInt64();
        }

        internal static SafeCreateHandle CFArrayGetValueAtIndex(SafeCFArrayHandle cfArray, int index)
        {
            return CFArrayGetValueAtIndex(cfArray, new CFIndex(index));
        }
    }
}

namespace Microsoft.Win32.SafeHandles
{
    internal sealed class SafeCFArrayHandle : SafeHandle
    {
        internal SafeCFArrayHandle()
            : base(IntPtr.Zero, ownsHandle: true)
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
