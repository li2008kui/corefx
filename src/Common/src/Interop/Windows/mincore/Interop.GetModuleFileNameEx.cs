// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal partial class Interop
{
    internal partial class mincore
    {
        [DllImport(Libraries.Psapi_Obsolete, CharSet = CharSet.Unicode, SetLastError = true, BestFitMapping = false, EntryPoint = "K32GetModuleFileNameExW")]
        internal static extern int GetModuleFileNameEx(SafeProcessHandle processHandle, IntPtr moduleHandle, [Out] char[] baseName, int size);
    }
}
