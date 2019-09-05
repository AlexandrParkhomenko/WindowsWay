
#define UNICODE 1  //will use unicode
#define _UNICODE 1 //we will use functions with prefixes _t

#pragma comment( lib, "shlwapi.lib" )

#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <Tlhelp32.h> // otherwise it will be difficult to search for the process.
#include <strsafe.h>

#include <commdlg.h>
// Global variables
LPCTSTR ptrszAppName = (LPCTSTR)L"I N J E C T";
HINSTANCE g_hInstance = NULL;
DWORD dw0 = 0; //NtCreateThreadEx
DWORD dw1 = 0;
void ErrorExit(LPTSTR lpszFunction)
{
	// We get a system message for the last error ( last-error )

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	// Error message output and exit

	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}
BOOL IsWow64(HANDLE hProcess2)
{
	typedef BOOL(WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;
	BOOL bIsWow64 = FALSE;
	// WOW64 is the x86 emulator that allows 32-bit Windows-based applications to run seamlessly on 64-bit Windows. 
	//IsWow64Process( (HANDLE) dwProcessId, bool Wow64Process);

	//IsWow64Process is not available on all supported versions of Windows.
	//Use GetModuleHandle to get a handle to the DLL that contains the function
	//and GetProcAddress to get a pointer to the function if available.

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
		GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != fnIsWow64Process)
	{
		if (!fnIsWow64Process(hProcess2, &bIsWow64))
		{
			//handle error
		}
	}
	return bIsWow64;
}
void RemoveFilenameFromPath(wchar_t *pszPath, size_t len)
{
	while (len && *(pszPath + len) != '\\') len--;
	if (len) *(pszPath + len + 1) = '\0';
}
bool PromptForFile(wchar_t *pszSelectedFile, wchar_t *pszFilter, wchar_t *pszTitle)
{
	OPENFILENAMEW ofn;
	memset(&ofn, 0, sizeof(ofn));

	ofn.lStructSize = sizeof(ofn);
	ofn.hInstance = g_hInstance;
	ofn.nFilterIndex = 1;
	ofn.lpstrFile = pszSelectedFile;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = pszFilter;
	ofn.lpstrTitle = pszTitle;
	ofn.Flags = OFN_FILEMUSTEXIST;

	return (GetOpenFileName(&ofn) != 0);
}
HANDLE NtCreateThreadEx(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback)
{
	typedef struct
	{
		ULONG Length;
		ULONG Unknown1;
		ULONG Unknown2;
		PULONG Unknown3;
		ULONG Unknown4;
		ULONG Unknown5;
		ULONG Unknown6;
		PULONG Unknown7;
		ULONG Unknown8;

	} UNKNOWN;

	typedef DWORD WINAPI NtCreateThreadEx_PROC(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD Unknown1,
		DWORD Unknown2,
		LPVOID Unknown3
	);
	UNKNOWN Buffer;
	memset(&Buffer, 0, sizeof(UNKNOWN));

	Buffer.Length = sizeof(UNKNOWN);
	Buffer.Unknown1 = 0x10003;
	Buffer.Unknown2 = 0x8;
	Buffer.Unknown3 = &dw1;
	Buffer.Unknown4 = 0;
	Buffer.Unknown5 = 0x10004;
	Buffer.Unknown6 = 4;
	Buffer.Unknown7 = &dw0;
	NtCreateThreadEx_PROC* VistaCreateThread = (NtCreateThreadEx_PROC*)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateThreadEx");

	if (VistaCreateThread == NULL)
		return NULL;

	HANDLE hRemoteThread = NULL;
	HRESULT hRes = 0;

	if (!SUCCEEDED(hRes = VistaCreateThread(
		&hRemoteThread,
		0x1FFFFF, // all access
		NULL,
		hProcess,
		(LPTHREAD_START_ROUTINE)lpRemoteThreadStart,
		lpRemoteCallback,
		FALSE,
		NULL,
		NULL,
		NULL,
		&Buffer
	)))
	{
		return NULL;
	}

	return hRemoteThread;
}
HANDLE MyCreateRemoteThread(HANDLE hProcess, LPVOID lpRemoteThreadStart, LPVOID lpRemoteCallback)
{
	if (GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx"))
	{
		//MessageBox(0,L"1",0,0);
		return NtCreateThreadEx(hProcess, lpRemoteThreadStart, lpRemoteCallback);
	}

	else
	{
		MessageBox(0, L"CreateRemoteThread", 0, 0);
		return CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpRemoteThreadStart, lpRemoteCallback, 0, 0);
	}

	return NULL;
}
int InjectDll(wchar_t *pszDllPath, size_t len, PROCESS_INFORMATION *ppi)
{
	HANDLE hRemoteThread;
	FARPROC lpLocLoadLibraryW;
	LPVOID lpRemoteMem;
	DWORD dwNumBytesWritten;

	// Get size of path string
	size_t nWriteSize = (len + 1) * sizeof(wchar_t);
	//->
	ppi->hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)ppi->hProcess);
	if (ppi->hProcess == NULL) {
		ErrorExit(TEXT("OpenProcess"));
	}
	if (IsWow64(ppi->hProcess)) {
		//MessageBox(0,TEXT("The process is running under WOW64. 32-bit app"),ptrszAppName,0);
	}
	else {
		//MessageBox(0,TEXT("The process is not running under WOW64. 64-bit app"),ptrszAppName,0);
	}

	// Alloc remote mem
	if ((lpRemoteMem = VirtualAllocEx(ppi->hProcess, NULL, nWriteSize, MEM_COMMIT, PAGE_READWRITE)) == NULL)
	{
		return 1;
	}

	// Get needed API addresses
	if ((lpLocLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW")) == NULL)
	{
		VirtualFreeEx(ppi->hProcess, lpRemoteMem, nWriteSize, MEM_RELEASE);
		return 2;
	}

	// Write path to remote mem
	if (WriteProcessMemory(ppi->hProcess, lpRemoteMem, pszDllPath, nWriteSize, (SIZE_T *)&dwNumBytesWritten) == false)
	{
		VirtualFreeEx(ppi->hProcess, lpRemoteMem, nWriteSize, MEM_RELEASE);
		return 3;
	}

	// Inject
	if ((hRemoteThread = MyCreateRemoteThread(ppi->hProcess, lpLocLoadLibraryW, lpRemoteMem)) == NULL)
	{
		VirtualFreeEx(ppi->hProcess, lpRemoteMem, nWriteSize, MEM_RELEASE);
		return 4;
	}

	// Wait for handle to have sex with door
	if (WaitForSingleObject(hRemoteThread, 5000) != WAIT_OBJECT_0)
	{
		VirtualFreeEx(ppi->hProcess, lpRemoteMem, nWriteSize, MEM_RELEASE);
		return 5;
	}

	VirtualFreeEx(ppi->hProcess, lpRemoteMem, nWriteSize, MEM_RELEASE);
	return 0;
}
int SetDebugPrivileges()
{
	DWORD err = 0;
	TOKEN_PRIVILEGES Debug_Privileges;
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid)) return GetLastError();

	HANDLE hToken = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
		return err;
	}

	Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	Debug_Privileges.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, NULL, NULL))
	{
		err = GetLastError();
		if (hToken) CloseHandle(hToken);
	}

	return err;
}
HANDLE GetProcessIdByName(LPCTSTR lpstrProcessName)
{
	int flagFirst = 0;
	HANDLE    dwProcessId = 0;
	//MessageBoxW(0,(LPCWSTR)lpstrProcessName,L"Message",0);
	HANDLE    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32    pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32))
		{
			do {
				if (lstrcmpi((LPCTSTR)pe32.szExeFile, (LPCTSTR)lpstrProcessName) == 0)
				{
					dwProcessId = (HANDLE)pe32.th32ProcessID;
					if (flagFirst == 0) { flagFirst = 1; }
					else { break; break; }
					//
				}
				//MessageBoxW(0,(LPCWSTR)pe32.szExeFile,(LPCWSTR)lpstrProcessName,0);
			} while (Process32Next(hSnapshot, &pe32));
		}
		CloseHandle(hSnapshot);
	}
	return dwProcessId;
}
int main() {

	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	wchar_t szInjectPath[MAX_PATH];
	wchar_t szInjectName[MAX_PATH];
	wchar_t szInjectCfg[MAX_PATH];
	wchar_t szInjectDll[MAX_PATH];
	wchar_t szTargetFile[MAX_PATH], wcsTargetPathOnly[MAX_PATH];
	wchar_t szTargetCmdLine[1024];

	ZeroMemory(&szTargetFile, sizeof(szTargetFile));
	ZeroMemory(&szTargetCmdLine, sizeof(szTargetCmdLine));

	///g_hInstance = hInstance;

	// Set debug privileges for injection
	SetDebugPrivileges();

	// Get this path & name
	DWORD dwLen = GetModuleFileName(NULL, szInjectPath, sizeof(szInjectPath));

	StringCchPrintf(szInjectName, sizeof(szInjectName), szInjectPath); //wcscpy_s
	PathStripPath(szInjectName);
	*(wcsstr(szInjectName, L".exe")) = 0; // Strip extension

	RemoveFilenameFromPath(szInjectPath, dwLen); // Strip name from path

												 // Build app paths
	StringCchPrintf(szInjectCfg, sizeof(szInjectCfg), L"%s%s.ini", szInjectPath, szInjectName);
	StringCchPrintf(szInjectDll, sizeof(szInjectDll), L"%s%s.dll", szInjectPath, szInjectName);

	// Check if cfg file exists
	if (PathFileExists(szInjectCfg) == false)
	{
		// Create a cfg
		HANDLE hCfgFile = CreateFileW(szInjectCfg, 0, 0, 0, NULL, CREATE_NEW, NULL);
		CloseHandle(hCfgFile);

		// Enter keys
		WritePrivateProfileString(L"Target Injection", L"Path", L"", szInjectCfg);
		WritePrivateProfileString(L"Target Injection", L"CommandLine", L"", szInjectCfg);
	}
	else
	{
		// Read config options
		GetPrivateProfileString(L"Target Injection", L"Path", NULL, szTargetFile, sizeof(szTargetFile), szInjectCfg);
		PathRemoveBlanks(szTargetFile);

		GetPrivateProfileString(L"Target Injection", L"CommandLine", NULL, szTargetCmdLine, sizeof(szTargetCmdLine), szInjectCfg);
	}

	// Prompt for target path if its invalid
	if (PathFileExists(szTargetFile) == false)
	{
		if (PromptForFile(szTargetFile, L"Executables\0*.exe\0\0", L"Browse to the target executable") == false)
		{
			MessageBox(GetForegroundWindow(), L"You didn't select a target executable!", L"Error", MB_ICONERROR | MB_TOPMOST);
			return 0;
		}
	}

	// Write path to cfg
	WritePrivateProfileString(L"Target Injection", L"Path", szTargetFile, szInjectCfg);

	// Check if dll exists
	if (PathFileExists(szInjectDll) == false)
	{
		wchar_t wcMsg[128];
		StringCchPrintf(wcMsg, sizeof(wcMsg), L"Could not find %s.dll to inject!\0", szInjectName); //wsprintf
		MessageBox(GetForegroundWindow(), wcMsg, L"Error", MB_ICONERROR | MB_TOPMOST);
		return 0;
	}

	// Create target process
	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));
	si.cb = sizeof(si);

	StringCchPrintf(wcsTargetPathOnly, sizeof(wcsTargetPathOnly), szTargetFile); //wcscpy_s
	RemoveFilenameFromPath(wcsTargetPathOnly, wcslen(wcsTargetPathOnly));

	if (CreateProcess(szTargetFile, szTargetCmdLine, NULL, NULL, FALSE, 0, NULL, wcsTargetPathOnly, &si, &pi) == false)//CREATE_SUSPENDED
	{
		MessageBox(GetForegroundWindow(), L"Failed to create the target process!", L"Error", MB_ICONERROR | MB_TOPMOST);
		return 0;
	}
	//Sleep(500); // Our project is protected by trash Armadilla. We start without suspension and wait a bit.
	//->	
	//HANDLE dwProcessId;
	PathStripPath(szTargetFile);
	MessageBox(GetForegroundWindow(), (LPCTSTR)szTargetFile, L"szTargetFile", MB_ICONERROR | MB_TOPMOST);
	LPCTSTR argv = (LPCTSTR)szTargetFile;
	pi.hProcess = (HANDLE)GetProcessId(pi.hProcess);
	//dwProcessId = GetProcessIdByName(argv);
	if (pi.hProcess == 0) { //dwProcessId
		ErrorExit(TEXT("Couldn't find the process...\n\n"));
	}
	//pi.hProcess = dwProcessId;

	// Inject the dll
	if (InjectDll(szInjectDll, wcslen(szInjectDll), &pi) != 0)
	{
		MessageBox(GetForegroundWindow(), L"Failed to inject the dll!", L"Error", MB_ICONERROR | MB_TOPMOST);
		TerminateProcess(pi.hProcess, -1);
		return 0;
	}
	/*
	
	VirtualProtect
	.RSRCSEC

	CloseHandle
	CreateFileA
	CreateThread
	ReadFile
	SetFilePointer
	Sleep
	VirtualProtect
	MessageBoxA
	
	*/

	// Allow the target to run
	ResumeThread(pi.hThread);

	// Cleanup
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return 0;
}
