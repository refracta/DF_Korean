#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

# define TARGET_EXE "Dwarf Fortress.exe"
# define MY_DLL_NAME "Dwarf_hook.dll"

bool RvaToPointer(DWORD rva, BYTE* base, PIMAGE_NT_HEADERS64 nt, BYTE** out)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        DWORD sectionStart = section->VirtualAddress;
        DWORD sectionEnd = sectionStart + section->SizeOfRawData;
        if (rva >= sectionStart && rva < sectionEnd) {
            *out = base + section->PointerToRawData + (rva - sectionStart);
            return true;
        }
    }
    return false;
}

bool CheckDllDependencies(const char* dllPath, const char* dllDir)
{
    HANDLE file = CreateFileA(dllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("[Error] Could not open DLL for dependency scan (%lu).\n", GetLastError());
        return false;
    }

    HANDLE mapping = CreateFileMappingA(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) {
        printf("[Error] Could not create mapping for DLL (%lu).\n", GetLastError());
        CloseHandle(file);
        return false;
    }

    BYTE* view = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        printf("[Error] Could not map DLL into memory (%lu).\n", GetLastError());
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)view;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[Error] Invalid DOS signature in DLL.\n");
        UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(view + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf("[Error] Unexpected PE header (not a 64-bit DLL?).\n");
        UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0 || importDir.VirtualAddress == 0) {
        UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);
        return true; // no imports to check
    }

    BYTE* importPtr = NULL;
    if (!RvaToPointer(importDir.VirtualAddress, view, nt, &importPtr)) {
        printf("[Error] Could not resolve import directory RVA.\n");
        UnmapViewOfFile(view);
        CloseHandle(mapping);
        CloseHandle(file);
        return false;
    }

    bool allFound = true;
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)importPtr;
    printf(" - Dependency scan (from DLL import table):\n");
    for (; importDesc->Name != 0; ++importDesc) {
        BYTE* namePtr = NULL;
        if (!RvaToPointer(importDesc->Name, view, nt, &namePtr)) {
            printf("   -> [Error] Could not resolve import name RVA.\n");
            allFound = false;
            continue;
        }

        char resolved[MAX_PATH];
        bool foundNearby = SearchPathA(dllDir, (const char*)namePtr, NULL, MAX_PATH, resolved, NULL) != 0;
        bool foundSystem = false;
        if (!foundNearby) {
            foundSystem = SearchPathA(NULL, (const char*)namePtr, NULL, MAX_PATH, resolved, NULL) != 0;
        }

        if (foundNearby || foundSystem) {
            printf("   -> %s : FOUND (%s)\n", (const char*)namePtr, resolved);
        } else {
            printf("   -> %s : MISSING (copy to game folder)\n", (const char*)namePtr);
            allFound = false;
        }
    }

    UnmapViewOfFile(view);
    CloseHandle(mapping);
    CloseHandle(file);
    return allFound;
}

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

    char dllDir[MAX_PATH];
    strcpy_s(dllDir, MAX_PATH, full_dll_path);
    char* lastSlash = strrchr(dllDir, '\\');
    if (lastSlash) {
        *(lastSlash + 1) = '\0';
    }

    if (!CheckDllDependencies(full_dll_path, dllDir)) {
        printf("[Error] Missing or unreadable dependency detected above; fix before launching.\n");
        system("pause");
        return 1;
    }

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

    if (exitCode == 0 && !dllLoaded) {
        printf(" - Injection Result: FAILURE (LoadLibrary returned 0 and module not visible)\n");
        if (snapshotError != 0) {
            printf("   -> Module snapshot error: GetLastError() = %lu (try running as administrator).\n", snapshotError);
        }
        printf("   -> Check architecture matches (both launcher/DLL built as x64).\n");
        printf("   -> Ensure MinHook.x64.dll and other dependencies are in the same folder.\n");
        printf("   -> Security software may block injection; try whitelisting.\n");
        CloseHandle(hThread);
        VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        system("pause");
        return 1;
    } else if (exitCode == 0 && dllLoaded) {
        printf(" - Injection Result: SUCCESS (LoadLibrary returned 0, module detected via snapshot)\n");
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