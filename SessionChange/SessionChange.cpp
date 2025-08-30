#include <Windows.h>
#include <WtsApi32.h>
#include <iostream>
#include <sddl.h>

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Advapi32.lib")

BOOL EnablePrivilege(LPCTSTR privilege) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
        
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return FALSE;
    }
    CloseHandle(hToken);
    return TRUE;
}

DWORD GetFirstActiveUserSession() {
    DWORD sessionId = 0;
    WTS_SESSION_INFOW* pSessionInfo = nullptr;
    DWORD sessionCount = 0;

    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; i++) {
            if (pSessionInfo[i].State == WTSActive && pSessionInfo[i].SessionId != 0) {
                sessionId = pSessionInfo[i].SessionId;
                break;
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
    return sessionId;
}

BOOL IsUserAdmin(HANDLE hToken) {
    BOOL isAdmin = FALSE;
    DWORD dwSize = 0;
    PTOKEN_GROUPS pGroupInfo = nullptr;

    if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        pGroupInfo = (PTOKEN_GROUPS)GlobalAlloc(GPTR, dwSize);
        if (pGroupInfo && GetTokenInformation(hToken, TokenGroups, pGroupInfo, dwSize, &dwSize)) {
            SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
            PSID AdministratorsGroup = nullptr;
            if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
                for (DWORD i = 0; i < pGroupInfo->GroupCount; i++) {
                    if (EqualSid(AdministratorsGroup, pGroupInfo->Groups[i].Sid)) {
                        isAdmin = TRUE;
                        break;
                    }
                }
                FreeSid(AdministratorsGroup);
            }
        }
        GlobalFree(pGroupInfo);
    }
    return isAdmin;
}

HANDLE GetElevatedToken(HANDLE hToken) {
    HANDLE hElevatedToken = nullptr;
    TOKEN_LINKED_TOKEN linkedToken = { 0 };
    DWORD dwSize = 0;

    if (GetTokenInformation(hToken, TokenLinkedToken, &linkedToken, sizeof(linkedToken), &dwSize)) {
        hElevatedToken = linkedToken.LinkedToken;
    }
    else if (GetLastError() == ERROR_NO_TOKEN) {
        if (IsUserAdmin(hToken)) {
            DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hElevatedToken);
        }
    }
    return hElevatedToken;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    DWORD currentSessionId;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &currentSessionId)) {
        MessageBoxW(NULL, L"Failed to get current session ID.", L"Error", MB_ICONERROR);
        return 1;
    }

    if (currentSessionId == 0) {
        if (!EnablePrivilege(SE_TCB_NAME) || !EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME) || !EnablePrivilege(SE_INCREASE_QUOTA_NAME)) {
            MessageBoxW(NULL, L"Failed to enable necessary privileges.", L"Error", MB_ICONERROR);
            return 1;
        }
        
        DWORD targetSessionId = GetFirstActiveUserSession();
        if (targetSessionId == 0) {
            MessageBoxW(NULL, L"No active user session found.", L"Error", MB_ICONERROR);
            return 1;
        }

        HANDLE hUserToken;
        if (!WTSQueryUserToken(targetSessionId, &hUserToken)) {
            MessageBoxW(NULL, L"Failed to get user token.", L"Error", MB_ICONERROR);
            return 1;
        }
        HANDLE hElevatedToken = GetElevatedToken(hUserToken);
        CloseHandle(hUserToken);

        if (!hElevatedToken) {
            MessageBoxW(NULL, L"Failed to get elevated token.", L"Error", MB_ICONERROR);
            return 1;
        }

        WCHAR modulePath[MAX_PATH];
        GetModuleFileNameW(NULL, modulePath, MAX_PATH);

        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        wchar_t desktop[] = L"winsta0\\default";
        si.lpDesktop = desktop;

        
        
        if (CreateProcessAsUserW(hElevatedToken, modulePath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            MessageBoxW(NULL, L"Failed to create elevated process in user session.", L"Error", MB_ICONERROR);
            CloseHandle(hElevatedToken);
            return 1;
        }

        CloseHandle(hElevatedToken);
        return 0;
    }

    MessageBoxW(NULL, L"Application is running in user session.", L"Info", MB_ICONINFORMATION);
    return 0;
}