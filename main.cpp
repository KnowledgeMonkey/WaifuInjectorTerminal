#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <commdlg.h>
#include <psapi.h>  // Required for EnumProcessModules and GetModuleBaseName
#pragma comment(lib, "Psapi.lib")  // Link against Psapi.lib for EnumProcessModules

#define MAX_PATH_LEN 255

// Function to set console text color
void SetConsoleColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}

// Function to print "Waifu Injector" in large text
void PrintTitle() {
    SetConsoleColor(10);  // Set color to Green (for the title)
    std::wcout << L"==============================\n";
    std::wcout << L" Waifu Injector V1\n";
    std::wcout << L"==============================\n";
    SetConsoleColor(7);  // Reset to default color
}

// Function to print author information in smaller text
void PrintAuthor() {
    SetConsoleColor(8);  // Set color to Dark Gray for the author message
    std::wcout << L"Made by Nox with love <3\n";
    SetConsoleColor(7);  // Reset to default color
}

// Function to enumerate all processes
std::vector<DWORD> EnumProcesses() {
    std::vector<DWORD> processIDs;
    DWORD processList[1024], cbNeeded, processCount;

    if (!EnumProcesses(processList, sizeof(processList), &cbNeeded))
        return processIDs;

    processCount = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < processCount; i++) {
        if (processList[i] != 0)
            processIDs.push_back(processList[i]);
    }

    return processIDs;
}

// Function to get process name from PID
std::wstring GetProcessName(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        wchar_t processName[MAX_PATH_LEN] = L"<unknown>";  // Use wchar_t for wide strings
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameW(hProcess, hMod, processName, sizeof(processName) / sizeof(wchar_t));  // Use GetModuleBaseNameW for wide strings
        }
        CloseHandle(hProcess);
        return std::wstring(processName);
    }
    return L"";
}

// Function to inject DLL into target process
bool InjectDLL(DWORD pid, const wchar_t* dllPath) {  // Use wchar_t* for wide strings
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL)
        return false;

    // Allocate memory in the target process
    void* allocMem = VirtualAllocEx(hProcess, NULL, wcslen(dllPath) * sizeof(wchar_t) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (allocMem == NULL) {
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the target process memory
    WriteProcessMemory(hProcess, allocMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    // Get the address of LoadLibraryW (wide-character version)
    FARPROC loadLibraryAddr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    // Create a remote thread in the target process to load the DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocMem, 0, NULL);
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the thread to finish and clean up
    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, allocMem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}

// Function to display a list of processes
void ListProcesses() {
    std::vector<DWORD> processes = EnumProcesses();
    std::wcout << L"Running Processes:" << std::endl;
    int index = 1;
    for (DWORD pid : processes) {
        std::wstring processName = GetProcessName(pid);  // Get process name as wide string
        std::wcout << index++ << L". " << L"PID: " << pid << L" - Process: " << processName << std::endl;
    }
    std::wcout << std::endl;
}

// Function to prompt user for process selection
DWORD SelectProcess() {
    ListProcesses();
    DWORD selectedPID;
    std::wcout << L"Enter the PID of the process to inject into: ";
    std::wcin >> selectedPID;
    return selectedPID;
}

// Function to open a file dialog for DLL selection
std::wstring SelectDLL() {
    OPENFILENAME ofn;
    wchar_t dllPath[MAX_PATH] = L"";
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetConsoleWindow();
    ofn.lpstrFile = dllPath;
    ofn.nMaxFile = sizeof(dllPath) / sizeof(wchar_t);
    ofn.lpstrFilter = L"DLL Files\0*.DLL\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.lpstrTitle = L"Select DLL File";
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn) == TRUE) {
        return std::wstring(dllPath);
    }
    return L"";
}

int main() {
    DWORD selectedPID = 0;
    std::wstring selectedDLL;

    // Display the title and author info
    PrintTitle();
    PrintAuthor();

    // Main menu loop
    while (true) {
        // Display menu
        SetConsoleColor(14);  // Set color to Yellow for menu
        std::wcout << L"Menu:" << std::endl;
        std::wcout << L"1. Select Process/Search Process" << std::endl;
        std::wcout << L"2. Select DLL" << std::endl;
        std::wcout << L"3. Inject DLL" << std::endl;
        std::wcout << L"4. Exit" << std::endl;
        SetConsoleColor(7);  // Reset to default color
        std::wcout << L"Choose an option (1-4): ";

        int choice;
        std::wcin >> choice;

        switch (choice) {
        case 1:  // Select Process
            selectedPID = SelectProcess();
            break;

        case 2:  // Select DLL
            selectedDLL = SelectDLL();
            if (selectedDLL.empty()) {
                std::wcout << L"Failed to select DLL!" << std::endl;
            }
            else {
                std::wcout << L"Selected DLL: " << selectedDLL << std::endl;
            }
            break;

        case 3:  // Inject DLL
            if (selectedPID == 0 || selectedDLL.empty()) {
                std::wcout << L"Please select a process and a DLL first!" << std::endl;
            }
            else {
                if (InjectDLL(selectedPID, selectedDLL.c_str())) {
                    SetConsoleColor(10);  // Green for success
                    std::wcout << L"DLL Injected Successfully!" << std::endl;
                    SetConsoleColor(7);  // Reset to default color
                }
                else {
                    SetConsoleColor(12);  // Red for error
                    std::wcout << L"DLL Injection Failed!" << std::endl;
                    SetConsoleColor(7);  // Reset to default color
                }
            }
            break;

        case 4:  // Exit
            std::wcout << L"Exiting..." << std::endl;
            return 0;

        default:
            std::wcout << L"Invalid choice, please try again." << std::endl;
        }

        std::wcout << std::endl;  // Add a blank line after each operation
    }

    return 0;
}
