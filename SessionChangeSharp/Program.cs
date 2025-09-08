using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace ElevatedSessionLauncher
{
    class Program
    {
        static void Main()
        {
            uint currentSessionId;
            if (!ProcessIdToSessionId((uint)Process.GetCurrentProcess().Id, out currentSessionId))
            {
                WriteError("Failed to get current session ID. Error: " + Marshal.GetLastWin32Error());
                return;
            }

            WriteLog($"Current session ID: {currentSessionId}");

            if (currentSessionId == 0)
            {
                // Enable required privileges
                if (!EnablePrivilege("SeTcbPrivilege"))
                    WriteError("Failed to enable SeTcbPrivilege");
                if (!EnablePrivilege("SeAssignPrimaryTokenPrivilege"))
                    WriteError("Failed to enable SeAssignPrimaryTokenPrivilege");
                if (!EnablePrivilege("SeIncreaseQuotaPrivilege"))
                    WriteError("Failed to enable SeIncreaseQuotaPrivilege");

                uint targetSessionId = GetFirstActiveUserSession();
                WriteLog($"Target session ID: {targetSessionId}");

                if (targetSessionId == 0)
                {
                    WriteError("No active user session found.");
                    return;
                }

                IntPtr hUserToken = IntPtr.Zero;
                if (!WTSQueryUserToken(targetSessionId, out hUserToken))
                {
                    WriteError("Failed to get user token. Error: " + Marshal.GetLastWin32Error());
                    return;
                }

                IntPtr hElevatedToken = GetElevatedToken(hUserToken);
                CloseHandle(hUserToken);

                if (hElevatedToken == IntPtr.Zero)
                {
                    WriteError("Failed to get elevated token. Error: " + Marshal.GetLastWin32Error());
                    return;
                }

                string modulePath = Process.GetCurrentProcess().MainModule.FileName;
                WriteLog($"Module path: {modulePath}");

                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "winsta0\\default";

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                if (CreateProcessAsUser(
                    hElevatedToken,
                    modulePath,
                    null,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    0,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi))
                {
                    WriteLog("Successfully launched elevated process in user session");
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else
                {
                    WriteError("Failed to create elevated process. Error: " + Marshal.GetLastWin32Error());
                }

                CloseHandle(hElevatedToken);
            }
            else
            {
                WriteLog("Application is running in user session.");
                Thread.Sleep(10000);
            }
        }

        private static void WriteError(string message)
        {
            WriteToFile("ERROR: " + message);
        }

        private static void WriteLog(string message)
        {
            WriteToFile("INFO: " + message);
        }

        private static void WriteToFile(string message)
        {
            string logPath = @"C:\Windows\Temp\sessionChange.txt";
            try
            {
                string logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}{Environment.NewLine}";
                File.AppendAllText(logPath, logMessage);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write to log file: {ex.Message}");
            }
        }

        private static bool EnablePrivilege(string privilegeName)
        {
            IntPtr hToken;
            if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken)) // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            {
                WriteError($"OpenProcessToken failed: {Marshal.GetLastWin32Error()}");
                return false;
            }

            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, privilegeName, out luid))
                {
                    WriteError($"LookupPrivilegeValue failed for {privilegeName}: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.PrivilegeCount = 1;
                tp.Privileges = new LUID_AND_ATTRIBUTES[1];
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED

                if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    WriteError($"AdjustTokenPrivileges failed for {privilegeName}: {Marshal.GetLastWin32Error()}");
                    return false;
                }

                // Check if the privilege was actually enabled
                int lastError = Marshal.GetLastWin32Error();
                if (lastError == 1300) // ERROR_NOT_ALL_ASSIGNED
                {
                    WriteError($"Privilege {privilegeName} not assigned: {lastError}");
                    return false;
                }

                WriteLog($"Successfully enabled privilege: {privilegeName}");
                return true;
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        private static uint GetFirstActiveUserSession()
        {
            IntPtr ppSessionInfo = IntPtr.Zero;
            int sessionCount = 0;
            uint sessionId = 0;

            if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref ppSessionInfo, ref sessionCount))
            {
                IntPtr current = ppSessionInfo;
                for (int i = 0; i < sessionCount; i++)
                {
                    WTS_SESSION_INFO sessionInfo = (WTS_SESSION_INFO)Marshal.PtrToStructure(
                        current, typeof(WTS_SESSION_INFO));

                    WriteLog($"Session {sessionInfo.SessionId}: State = {sessionInfo.State}");

                    if (sessionInfo.State == WTS_CONNECTSTATE_CLASS.WTSActive && sessionInfo.SessionId != 0)
                    {
                        sessionId = sessionInfo.SessionId;
                        break;
                    }
                    current = (IntPtr)(current.ToInt64() + Marshal.SizeOf(typeof(WTS_SESSION_INFO)));
                }
                WTSFreeMemory(ppSessionInfo);
            }
            else
            {
                WriteError($"WTSEnumerateSessions failed: {Marshal.GetLastWin32Error()}");
            }
            return sessionId;
        }

        private static IntPtr GetElevatedToken(IntPtr hToken)
        {
            TOKEN_LINKED_TOKEN linkedToken = new TOKEN_LINKED_TOKEN();
            int returnLength;

            if (GetTokenInformation(
                hToken,
                TOKEN_INFORMATION_CLASS.TokenLinkedToken,
                out linkedToken,
                Marshal.SizeOf(linkedToken),
                out returnLength))
            {
                WriteLog("Successfully obtained elevated token");
                return linkedToken.LinkedToken;
            }

            WriteError($"GetTokenInformation failed: {Marshal.GetLastWin32Error()}");
            return IntPtr.Zero;
        }

        // Native methods and structures
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            int BufferLength,
            IntPtr PreviousState,
            IntPtr ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            out TOKEN_LINKED_TOKEN TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WTS_SESSION_INFO
        {
            public uint SessionId;
            public IntPtr pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        private enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_LINKED_TOKEN
        {
            public IntPtr LinkedToken;
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenLinkedToken = 19
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }
}