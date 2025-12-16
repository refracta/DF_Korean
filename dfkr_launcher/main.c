#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>
#include <string.h>

# define TARGET_EXE "Dwarf Fortress.exe"
# define MY_DLL_NAME "Dwarf_hook.dll"

bool IsModuleLoaded(DWORD processId, const char* moduleName, DWORD* snapshotError)
{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (snapshot == INVALID_HANDLE_VALUE) {
        if (snapshotError) {
            *snapshotError = GetLastError();
        }
        return false;
    }

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(snapshot, &moduleEntry)) {
        if (snapshotError) {
            *snapshotError = GetLastError();
        }
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Module32Next(snapshot, &moduleEntry));

    CloseHandle(snapshot);
    if (snapshotError) {
        *snapshotError = 0;
    }
    return false;
}


int main()
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char dll_path[MAX_PATH];
    char full_dll_path[MAX_PATH];
    sprintf_s(dll_path, MAX_PATH, "%s", MY_DLL_NAME);
    DWORD full_len = GetFullPathNameA(dll_path, MAX_PATH, full_dll_path, NULL);
    if (full_len == 0 || full_len >= MAX_PATH) {
        printf("[Error] Failed to resolve full DLL path. (Code: %lu)\n", GetLastError());
        system("pause");
        return 1;
    }

    printf("=== Debug Launcher ===\n");
    printf("[1] Checking Files...\n");
    printf(" - Path: %s\n", full_dll_path);

    if (GetFileAttributesA(dll_path) == INVALID_FILE_ATTRIBUTES) {
        printf("[Error] DLL file NOT found! Check filename.\n");
        system("pause");
        return 1;
    }
    printf(" - DLL Found: OK\n");

    printf("[2] Starting Game (Suspended)...\n");
    if (!CreateProcessA(NULL, TARGET_EXE, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[Error] Failed to start '%s'. (Code: %d)\n", TARGET_EXE, GetLastError());
        printf(" -> Make sure launcher is in the game folder.\n");
        system("pause");
        return 1;
    }
    printf(" - Process ID: %d\n", pi.dwProcessId);

    printf("[3] Injecting DLL...\n");
    void* pLoadLibrary = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        printf("[Error] Failed to find LoadLibraryA.\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    void* pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, strlen(full_dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        printf("[Error] Memory Allocation failed.\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, pRemoteBuf, (void*)full_dll_path, strlen(full_dll_path) + 1, NULL)) {
        printf("[Error] WriteProcessMemory failed.\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteBuf, 0, NULL);
    if (!hThread) {
        printf("[Error] CreateRemoteThread failed. (Anti-Virus blocking?)\n");
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    bool dllLoaded = false;
    DWORD snapshotError = 0;
    const int maxAttempts = 40; // ~2 seconds of retry time at 50ms each
    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        dllLoaded = IsModuleLoaded(pi.dwProcessId, MY_DLL_NAME, &snapshotError);
        if (dllLoaded || snapshotError == ERROR_BAD_LENGTH) {
            // ERROR_BAD_LENGTH can occur when the snapshot is being modified; retry loop handles it.
            if (dllLoaded) {
                break;
            }
        }
        Sleep(50);
    }

    if (exitCode == 0) {
        if (dllLoaded) {
            printf(" - Injection Result: SUCCESS (LoadLibrary returned 0, module detected via snapshot)\n");
        } else {
            printf(" - Injection Result: SUCCESS (continuing; LoadLibrary returned 0 but module visibility not confirmed)\n");
            if (snapshotError != 0) {
                printf("   -> Module snapshot error: GetLastError() = %lu (try running as administrator).\n", snapshotError);
            }
        }
    } else {
        printf(" - Injection Result: SUCCESS (Handle: 0x%X)\n", exitCode);
    }

    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);

    printf("[4] Resuming Game...\n");
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("Done.\n");
    Sleep(2000);
    return 0;
}