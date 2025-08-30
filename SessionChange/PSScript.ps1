Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

public class WinAPI {
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    public static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("advapi32.dll", SetLastError=true)]
	public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
	public static extern bool LookupPrivilegeValue(string lpSystemName,string lpName,ref long lpLuid);
			
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,bool DisableAllPrivileges,ref TokPriv1Luid NewState,int BufferLength,IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("wtsapi32.dll")]
    public static extern bool WTSEnumerateSessionsW(IntPtr hServer, int Reserved, int Version, ref IntPtr ppSessionInfo, ref int pCount);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AllocateAndInitializeSid(ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority, byte nSubAuthorityCount, uint dwSubAuthority0, uint dwSubAuthority1, uint dwSubAuthority2, uint dwSubAuthority3, uint dwSubAuthority4, uint dwSubAuthority5, uint dwSubAuthority6, uint dwSubAuthority7, out IntPtr pSid);

    [DllImport("advapi32.dll")]
    public static extern bool EqualSid(IntPtr pSid1, IntPtr pSid2);

    [DllImport("advapi32.dll")]
    public static extern void FreeSid(IntPtr pSid);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalAlloc(uint uFlags, uint dwBytes);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GlobalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILAGES
    {
        public int Count;
        public long Luid;
        public int Attr;
    }


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTS_SESSION_INFO {
        public uint SessionId;
        public string pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_IDENTIFIER_AUTHORITY {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_GROUPS {
        public uint GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_LINKED_TOKEN {
        public IntPtr LinkedToken;
    }

    public const uint TOKEN_QUERY = 0x0008;
    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_DUPLICATE = 0x0002;
    public const uint TOKEN_ASSIGN_PRIMARY = 0x0001;
    public const uint TOKEN_READ = 0x00020000;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    public const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    public const uint NORMAL_PRIORITY_CLASS = 0x00000020;
    public const int WTS_CURRENT_SERVER_HANDLE = 0;
    public const int WTSActive = 0;
    public const uint TokenGroups = 2;
    public const uint TokenLinkedToken = 19;
    public const int SecurityImpersonation = 2;
    public const int SecurityIdentification = 1;
    public const int TokenPrimary = 1;
    public const uint ERROR_NO_TOKEN = 1008;
    public const uint SECURITY_BUILTIN_DOMAIN_RID = 0x00000020;
    public const uint ERROR_INSUFFICIENT_BUFFER = 122;
    public const uint DOMAIN_ALIAS_RID_ADMINS = 0x00000220;
    public const uint MAXIMUM_ALLOWED = 0x02000000;
    public const uint GPTR = 0x0040;
}
"@

function Write-ToFile {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$String,

        [switch]$NoNewLine,
        
        [ValidateSet("ASCII", "BigEndianUnicode", "Default", "OEM", "Unicode", "UTF7", "UTF8", "UTF32")]
        [string]$Encoding = "UTF8"
    )
    $filePath = "C:\Windows\Temp\test.txt"
    $directory = Split-Path -Path $FilePath -Parent
    if ($directory -and !(Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    if ($NoNewLine) {
        Add-Content -Path $FilePath -Value $String -NoNewline -Encoding $Encoding
    } else {
        Add-Content -Path $FilePath -Value $String -Encoding $Encoding
    }
    return $true
}

function Enable-Privilege {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [string]$privilage
    )

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential, Pack = 1)]
	public struct TokPriv1Luid
	{
		public int Count;
		public long Luid;
		public int Attr;
	}
	
	public static class Advapi32
	{
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
			
		[DllImport("advapi32.dll", SetLastError=true)]
		public static extern bool LookupPrivilegeValue(
			string lpSystemName,
			string lpName,
			ref long lpLuid);
			
		[DllImport("advapi32.dll", SetLastError = true)]
		public static extern bool AdjustTokenPrivileges(
			IntPtr TokenHandle,
			bool DisableAllPrivileges,
			ref TokPriv1Luid NewState,
			int BufferLength,
			IntPtr PreviousState,
			IntPtr ReturnLength);
			
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll")]
		public static extern uint GetLastError();
	}
"@
	
	$ProcHandle = (Get-Process -Id ([System.Diagnostics.Process]::GetCurrentProcess().Id)).Handle
		
	# Open token handle with TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
	$hTokenHandle = [IntPtr]::Zero
	$CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x28, [ref]$hTokenHandle)
		
	# Prepare TokPriv1Luid container
	$TokPriv1Luid = New-Object TokPriv1Luid
	$TokPriv1Luid.Count = 1
	$TokPriv1Luid.Attr = 0x00000002 # SE_PRIVILEGE_ENABLED
			
	# Get SeBackupPrivilege luid
	$LuidVal = $Null
	$CallResult = [Advapi32]::LookupPrivilegeValue($null, $privilage, [ref]$LuidVal)
	$TokPriv1Luid.Luid = $LuidVal
			
	# Enable SeBackupPrivilege for the current process
	$CallResult = [Advapi32]::AdjustTokenPrivileges($hTokenHandle, $False, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    [WinAPI]::CloseHandle($ProcHandle)
    [WinAPI]::CloseHandle($hTokenHandle)
}

function Get-FirstActiveUserSession {
    $sessionId = 0
    $ppSessionInfo = [IntPtr]::Zero
    $pCount = 0

    if([WinAPI]::WTSEnumerateSessionsW([WinAPI]::WTS_CURRENT_SERVER_HANDLE, 0, 1, [ref]$ppSessionInfo, [ref]$pCount)) {
        $size = [Runtime.InteropServices.Marshal]::SizeOf([Type][WinAPI+WTS_SESSION_INFO])
        for($i = 0; $i -lt $pCount; $i++) {
            $pSession = [IntPtr]($ppSessionInfo.ToInt64() + $i * $size)
            $sessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($pSession, [Type][WinAPI+WTS_SESSION_INFO])
            if($sessionInfo.State -eq [WinAPI]::WTSActive -and $sessionInfo.SessionId -ne 0) {
                $sessionId = $sessionInfo.SessionId
                break
            }
        }
        [WinAPI]::WTSFreeMemory($ppSessionInfo)
    }
    return $sessionId
}

function Get-ElevatedToken {
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [IntPtr]$huToken
    )
    
    $hElevatedToken = [IntPtr]::Zero
    $dwSize = 0
    
    # First call to get the required buffer size
    $result = [WinAPI]::GetTokenInformation($huToken, [WinAPI]::TokenLinkedToken, [IntPtr]::Zero, 0, [ref]$dwSize)
    $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    Write-ToFile "First GetTokenInformation call - Required size: $dwSize, Last error: $lastError"
    
    if ($lastError -eq [WinAPI]::ERROR_INSUFFICIENT_BUFFER) {
        # Allocate the correct buffer size
        $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)
        
        try {
            if ([WinAPI]::GetTokenInformation($huToken, [WinAPI]::TokenLinkedToken, $buffer, $dwSize, [ref]$dwSize)) {
                $linkedToken = [System.Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [Type][WinAPI+TOKEN_LINKED_TOKEN])
                $hElevatedToken = $linkedToken.LinkedToken
                Write-ToFile "Got elevated token via linked token: $hElevatedToken"
                
                # If we got a linked token, duplicate it to ensure we have the right permissions
                $hDuplicatedToken = [IntPtr]::Zero
                if ([WinAPI]::DuplicateTokenEx($hElevatedToken, [WinAPI]::MAXIMUM_ALLOWED, [IntPtr]::Zero, 
                                              [WinAPI]::SecurityIdentification, [WinAPI]::TokenPrimary, 
                                              [ref]$hDuplicatedToken)) {
                    [WinAPI]::CloseHandle($hElevatedToken)
                    $hElevatedToken = $hDuplicatedToken
                    Write-ToFile "Duplicated linked token: $hElevatedToken"
                }
            } else {
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-ToFile "GetTokenInformation failed after buffer allocation: $lastError"
            }
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    }
    elseif ($lastError -eq [WinAPI]::ERROR_NO_TOKEN) {
        Write-ToFile "No linked token, checking admin group membership."
        if (Check-Admin -hcToken $huToken) {
            Write-ToFile "User is admin, duplicating token."
            $dupResult = [WinAPI]::DuplicateTokenEx($huToken, [WinAPI]::MAXIMUM_ALLOWED, [IntPtr]::Zero, 
                                                   [WinAPI]::SecurityIdentification, [WinAPI]::TokenPrimary, 
                                                   [ref]$hElevatedToken)
            if (-not $dupResult) {
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-ToFile "DuplicateTokenEx failed: $lastError"
            } else {
                Write-ToFile "DuplicateTokenEx succeeded, token: $hElevatedToken"
            }
        } else {
            Write-ToFile "User is not admin."
        }
    }
    else {
        Write-ToFile "GetTokenInformation for TokenLinkedToken failed: $lastError"
        
        # Fallback: Check if user is admin and try to duplicate the token
        Write-ToFile "Trying fallback method (admin check)"
        if (Check-Admin -hcToken $huToken) {
            Write-ToFile "User is admin, duplicating token (fallback)."
            $dupResult = [WinAPI]::DuplicateTokenEx($huToken, [رهWinAPI]::MAXIMUM_ALLOWED, [IntPtr]::Zero, 
                                                   [WinAPI]::SecurityIdentification, [WinAPI]::TokenPrimary, 
                                                   [ref]$hElevatedToken)
            if (-not $dupResult) {
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-ToFile "DuplicateTokenEx failed (fallback): $lastError"
            } else {
                Write-ToFile "DuplicateTokenEx succeeded (fallback), token: $hElevatedToken"
            }
        }
    }
    
    return $hElevatedToken
}


# Main execution
$currentSessionId = 0
if(-not [WinAPI]::ProcessIdToSessionId([WinAPI]::GetCurrentProcessId(), [ref]$currentSessionId))
{
    Write-ToFile "Failed to get current session ID.`n"
    exit 1
}

if($currentSessionId -eq 0)
{
    Enable-Privilege "SeAssignPrimaryTokenPrivilege"
    Enable-Privilege "SeIncreaseQuotaPrivilege"
    Enable-Privilege "SeTcbPrivilege"

    
       
    $targetSessionId = Get-FirstActiveUserSession
    if($targetSessionId -eq 0)
    {
        Write-ToFile "No active user session found.`n"
        exit 1
    }

    $hUserToken = [IntPtr]::Zero
    if(-not [WinAPI]::WTSQueryUserToken($targetSessionId, [ref]$hUserToken))
    {
        Write-ToFile "Failed to get user token.`n"
        exit 1
    }

    $hElevatedToken = Get-ElevatedToken -huToken $hUserToken
    [WinAPI]::CloseHandle($hUserToken)
    Write-ToFile "Elevated token is: $hElevatedToken.`n"
    

    if(-not $hElevatedToken)
    {
        Write-ToFile "Failed to get elevated token.`n"
        exit 1
    }

    $scriptPath = $MyInvocation.MyCommand.Definition
    $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    $startupInfo = New-Object WinAPI+STARTUPINFO
    $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf([Type][WinAPI+STARTUPINFO])
    $startupInfo.lpDesktop = "winsta0\default"

    $processInfo = New-Object WinAPI+PROCESS_INFORMATION
    
    if([WinAPI]::CreateProcessAsUserW($hElevatedToken, $powershellPath, "-File `"$scriptPath`"", [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, $null, [ref]$startupInfo, [ref]$processInfo))
    {
        [WinAPI]::CloseHandle($processInfo.hProcess)
        [WinAPI]::CloseHandle($processInfo.hThread)
    }
    else 
    {
        Write-ToFile "Failed to create elevated process in user session.`n"
        [WinAPI]::CloseHandle($hElevatedToken)
        exit 1
    }
    
    [WinAPI]::CloseHandle($hElevatedToken)
    exit 0
}

Write-ToFile "Application is running in user session.`n"
Start-Process C:\Windows\System32\mmc.exe