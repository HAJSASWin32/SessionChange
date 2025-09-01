Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();

    [DllImport("kernel32.dll")]
    public static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    public static extern bool WTSQueryUserToken(uint SessionId, out IntPtr phToken);

    [DllImport("wtsapi32.dll")]
    public static extern int WTSEnumerateSessions(
        System.IntPtr hServer,
        int Reserved,
        int Version,
        ref System.IntPtr ppSessionInfo,
        ref int pCount);

    [DllImport("wtsapi32.dll")]
    public static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(
        IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        uint TokenInformationLength,
        out uint ReturnLength);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);



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
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct TOKEN_LINKED_TOKEN {
        public IntPtr LinkedToken;
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        [MarshalAs(UnmanagedType.LPStr)] TokenUser = 1,
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
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        TokenLoggingInformation,
        TokenLearningMode,
        MaxTokenInfoClass
    }

    public const int WTS_CURRENT_SERVER_HANDLE = 0;
    public const int WTSActive = 0;
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

    if([WinAPI]::WTSEnumerateSessions([WinAPI]::WTS_CURRENT_SERVER_HANDLE, 0, 1, [ref]$ppSessionInfo, [ref]$pCount)) {
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
    $tokenInformationClass = [WinAPI+TOKEN_INFORMATION_CLASS]::TokenLinkedToken
    
    # Get the required buffer size first
    $returnLength = 0
    $result = [WinAPI]::GetTokenInformation($huToken, $tokenInformationClass, [IntPtr]::Zero, 0, [ref]$returnLength)
    $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
    if ($lastError -eq 122) { # ERROR_INSUFFICIENT_BUFFER
        # Allocate buffer with the correct size
        $buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($returnLength)
        try {
            $result = [WinAPI]::GetTokenInformation($huToken, $tokenInformationClass, $buffer, $returnLength, [ref]$returnLength)
            if ($result) {
                $linkedToken = [Runtime.InteropServices.Marshal]::PtrToStructure($buffer, [Type][WinAPI+TOKEN_LINKED_TOKEN])
                $hElevatedToken = $linkedToken.LinkedToken
            } else {
                $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-ToFile "GetTokenInformation failed with error: $lastError"
            }
        } finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        }
    } else {
        Write-ToFile "Failed to get buffer size. Error: $lastError"
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

    # $hElevatedToken = Get-ElevatedToken -huToken $hUserToken
    # [WinAPI]::CloseHandle($hUserToken)
    # Write-ToFile "Elevated token is: $hElevatedToken.`n"
    

    # if(-not $hElevatedToken)
    # {
    #     Write-ToFile "Failed to get elevated token.`n"
    #     exit 1
    # }

    $scriptPath = $MyInvocation.MyCommand.Definition
    $powershellPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    
    $startupInfo = New-Object WinAPI+STARTUPINFO
    $startupInfo.cb = [Runtime.InteropServices.Marshal]::SizeOf([Type][WinAPI+STARTUPINFO])
    $startupInfo.lpDesktop = "winsta0\default"

    $processInfo = New-Object WinAPI+PROCESS_INFORMATION
    
    if([WinAPI]::CreateProcessAsUserW($hUserToken, $powershellPath, "-File `"$scriptPath`"", [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, $null, [ref]$startupInfo, [ref]$processInfo))
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