/*
Skyrim 4GB Loader
Copyright (C) 2010,2011  Renee Stanley (the.wench@wenchy.net)

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "stdafx.h"
#include "resource.h"
#include <commctrl.h>
#include <mmsystem.h>
#include <shlwapi.h>
#include <shlobj.h>

HWND dialog = 0;

int Change4GBValue(LPVOID baseaddress, int set)
{
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>( baseaddress );
	if( pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{ 
		return -1; 
	}

	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	    (PBYTE)baseaddress + pDOSHeader->e_lfanew );

	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{ 
		return -1; 
	}

	PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>( 
		(PBYTE)&pNTHeader->FileHeader );

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		(PBYTE)&pNTHeader->OptionalHeader );

	/////////////////////////////////////////////////////////////
	if( IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic )
	{ 
		return -1; 
	}

	int ret = pFileHeader->Characteristics;

	if (set >= 0)
	{
		DWORD old;
		VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), PAGE_READWRITE, &old);

		if (set)
			pFileHeader->Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
		else
			pFileHeader->Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;

		DWORD oldold;
		VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), old, &oldold);
	}

	return (ret & IMAGE_FILE_LARGE_ADDRESS_AWARE)!=0;
}

void ShowError(LPTSTR title)
{
	LPVOID lpMsgBuf;
	DWORD dw = GetLastError(); 

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0, NULL );

	if (dialog) PostMessage(dialog,WM_USER,0,0);
	MessageBox(NULL, (LPTSTR) lpMsgBuf, title, MB_ICONERROR); 
	LocalFree(lpMsgBuf);

}

int Change4GBValue(LPTSTR filename, int set, WIN32_FILE_ATTRIBUTE_DATA *newatts=0)
{
	/////////////////////////////////////////////////////////////
	HANDLE hFile = CreateFile( filename, GENERIC_READ|(set>=0?GENERIC_WRITE:0), FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if ( hFile == INVALID_HANDLE_VALUE )
	{
		ShowError(TEXT("Error Opening executable"));
		return -1; 
	}

	/////////////////////////////////////////////////////////////
	HANDLE hFileMapping = CreateFileMapping( hFile, NULL,
		(set>=0?PAGE_READWRITE:PAGE_READONLY), 0, 0, NULL );
	if ( NULL == hFileMapping )
	{ 
		ShowError(TEXT("Error creating file mapping"));
		CloseHandle(hFile); 
		return -1; 
	}

	/////////////////////////////////////////////////////////////
	LPVOID pBaseAddress = MapViewOfFile( hFileMapping,
		(set>=0?FILE_MAP_WRITE:FILE_MAP_READ), 0, 0, 0 );
	if ( NULL == pBaseAddress )
	{ 
		ShowError(TEXT("Error mapping view"));
		CloseHandle(hFileMapping); 
		CloseHandle(hFile); 
		return -1; 
	}

	int original = Change4GBValue(pBaseAddress,set);

	UnmapViewOfFile(pBaseAddress);
	CloseHandle(hFileMapping); 

	if (newatts && set>=0) SetFileTime(hFile,&newatts->ftCreationTime,&newatts->ftLastAccessTime,&newatts->ftLastWriteTime);
	CloseHandle(hFile); 

	if (original == -1)
	{
		if (dialog) PostMessage(dialog,WM_USER,0,0);
		MessageBox(NULL,TEXT("Unable read executable."), TEXT("Error"), MB_ICONERROR);
		return -1;
	}

	return original;
}

LPTSTR FindLast(LPTSTR str, TCHAR c)
{
	LPTSTR last = 0;

	while(*str)
	{
		if (*str == c) last = str;
		str++;
	}

	return last;
}

LPCTSTR FindLast(LPCTSTR str, TCHAR c)
{
	LPCTSTR last = 0;

	while(*str)
	{
		if (*str == c) last = str;
		str++;
	}

	return last;
}

LPTSTR FindFirst(LPTSTR str, TCHAR c)
{
	while(*str)
	{
		if (*str == c) return str;
		str++;
	}

	return 0;
}

LPCTSTR FindFirst(LPCTSTR str, TCHAR c)
{
	while(*str)
	{
		if (*str == c) return str;
		str++;
	}

	return 0;
}

INT_PTR CALLBACK DialogFunc(HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
	switch(uMsg)
	{
	case WM_INITDIALOG:
		{
			dialog = hwndDlg;

			HWND progress = GetDlgItem(hwndDlg,IDC_PROGRESS1);
			SetWindowLongPtr(progress, GWL_STYLE, PBS_MARQUEE|WS_CHILD|WS_VISIBLE );

			SendMessage(      // returns LRESULT in lResult     
				(HWND) progress,      // handle to destination control     
				(UINT) PBM_SETRANGE32,      // message ID     
				(WPARAM) 0,      // = (WPARAM) (BOOL) wParam;    
				(LPARAM) 100      // = (LPARAM) (UINT) lParam; 
			);

			SendMessage(      // returns LRESULT in lResult     
				(HWND) progress,      // handle to destination control     
				(UINT) PBM_SETMARQUEE,      // message ID     
				(WPARAM) 1,      // = (WPARAM) (BOOL) wParam;    
				(LPARAM) 100      // = (LPARAM) (UINT) lParam; 
			);
		}
		break;

	case WM_USER:
		{
			dialog = 0;
			EndDialog(hwndDlg,0);
		}
		break;

	}
	
	return FALSE;
}

DWORD CALLBACK DialogThread(LPVOID hinstance)
{
	INITCOMMONCONTROLSEX InitCtrlEx;

	InitCtrlEx.dwSize = sizeof(INITCOMMONCONTROLSEX);
	InitCtrlEx.dwICC = ICC_PROGRESS_CLASS;
	InitCommonControlsEx(&InitCtrlEx);


	INT_PTR ret = DialogBox((HINSTANCE) hinstance,MAKEINTRESOURCE(IDD_DIALOG1),NULL,DialogFunc);
	if (ret == -1) ShowError(TEXT("Dialog"));
	return (DWORD) ret;
}

bool operator !=(const FILETIME &left, const FILETIME &right){
	return left.dwHighDateTime != right.dwHighDateTime || left.dwLowDateTime!= right.dwLowDateTime; 
}

int WinMainCRTStartup()
{
	DWORD dialogthreadid;
	HANDLE hdialogthread = CreateThread(0,0,DialogThread,(LPVOID)GetModuleHandle(NULL),0,&dialogthreadid);
	while (!dialog) Sleep(0);

	TCHAR this_name[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL),this_name,MAX_PATH);

	// Get our name
	TCHAR *slash = FindLast(this_name,'/');
	TCHAR *backslash = FindLast(this_name,'\\');
	INT_PTR size = 0;
	if (backslash && (!slash || backslash < slash)) size = 1 + backslash - this_name;
	else if (slash) size = 1 + slash - this_name;

	// want to make sure that we aren't called skyrim and going to cause an infinite loop
	TCHAR *dot = FindFirst(this_name+size, '.');
	if (!dot) {
		for (dot = this_name; *dot; dot++);
	}
	
	if (CompareString(LOCALE_INVARIANT, NORM_IGNORECASE, this_name+size,dot-(this_name+size),TEXT("TESV"),4) == CSTR_EQUAL)
	{
		if (dialog) PostMessage(dialog,WM_USER,0,0);
		MessageBox(NULL,TEXT("Skyrim4GB loader must not be named TESV.exe"), TEXT("Error"), MB_ICONERROR);
		return -1;
	}

	TCHAR skyrimpath[MAX_PATH+1] = TEXT("");
	
	HKEY regkey;
	if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Bethesda Softworks\\Skyrim"),&regkey) == ERROR_SUCCESS)
	{
		DWORD type;
		if (RegQueryValueEx(regkey,TEXT("Installed Path"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
		{
			DWORD skyrimpath_size = (MAX_PATH+1)*sizeof(TCHAR);
			if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("Installed Path"),NULL,&type,(LPBYTE) skyrimpath,&skyrimpath_size) == ERROR_SUCCESS)
			{
				if (type == REG_SZ || type == REG_EXPAND_SZ)
				{
					skyrimpath[MAX_PATH] = 0;				
				}
			}
		}
		RegCloseKey(regkey);
	}

	// Attempt to get it from steam
	if (!*skyrimpath) 
	{
		if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Valve\\Steam"),&regkey) == ERROR_SUCCESS)
		{
			DWORD type;
			if (RegQueryValueEx(regkey,TEXT("InstallPath"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
			{
				DWORD skyrimpath_size = (MAX_PATH+1)*sizeof(TCHAR);
				if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("InstallPath"),NULL,&type,(LPBYTE) skyrimpath,&skyrimpath_size) == ERROR_SUCCESS)
				{
					if (type == REG_SZ || type == REG_EXPAND_SZ)
					{
						skyrimpath[MAX_PATH] = 0;				
						PathAppend(skyrimpath,TEXT("steamapps\\common\\skyrim"));
					}
				}
			}
			RegCloseKey(regkey);
		}
	}


	if (*skyrimpath && !SetCurrentDirectory(skyrimpath))
	{
		ShowError(TEXT("Unable set current dir to Skyrim dir."));
		return -1;
	}

	WIN32_FILE_ATTRIBUTE_DATA TESV_exe_info, TESV_4gb_info;
	if (!GetFileAttributesEx(TEXT("TESV.exe"),GetFileExInfoStandard,&TESV_exe_info))
	{
		ShowError(TEXT("Unable to get file information about TESV.exe"));
		return -1;
	}

	bool updatereq = true;

	BOOL setbit = TRUE;

#ifdef ONLY_ON_WOW64
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS  fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if (!fnIsWow64Process || !fnIsWow64Process(GetCurrentProcess(),&setbit)) 
		setbit = FALSE;

	if (CompareString(LOCALE_INVARIANT, NORM_IGNORECASE, this_name+size,dot-(this_name+size),TEXT("skyrim4gb-force"),12) == CSTR_EQUAL)
	{
		setbit = TRUE;
	}
#endif

	// If the
	if (!GetFileAttributesEx(TEXT("TESV.exe.4gb"),GetFileExInfoStandard,&TESV_4gb_info) || 
		TESV_exe_info.ftCreationTime != TESV_4gb_info.ftCreationTime ||
		TESV_exe_info.ftLastWriteTime != TESV_4gb_info.ftLastWriteTime ||
		TESV_exe_info.nFileSizeHigh != TESV_4gb_info.nFileSizeHigh ||
		TESV_exe_info.nFileSizeLow != TESV_4gb_info.nFileSizeLow)
	{
		if (!CopyFile(TEXT("TESV.exe"),TEXT("TESV.exe.4gb"),FALSE))
		{
			ShowError(TEXT("Unable to copy TESV.exe to TESV.exe.4gb"));
			return -1;
		}
	}
	else {
		int res = Change4GBValue(TEXT("TESV.exe.4gb"), -1);

		if (res == -1) return -1;
		updatereq = (res != 0) != (setbit!=FALSE);
	}

	if (updatereq && Change4GBValue(TEXT("TESV.exe.4gb"), (setbit!=FALSE)?1:0, &TESV_exe_info) == -1)
	{
		return -1;		
	}

	LPTSTR commandLine = GetCommandLine();

	// Find the argument, if it exists
	bool quoted = false;
	while (*commandLine)
	{
		if (*commandLine=='\"') quoted = !quoted;
		else if (!quoted && *commandLine==' ') {
			commandLine++;
			break;
		}
		commandLine++;
	}

	if (!*commandLine) commandLine = TEXT("72850");

	if (!SetEnvironmentVariable(TEXT("SteamAPPId"),commandLine))
	{
		ShowError(TEXT("Unable to set SteamAppId"));
		return -1;
	}

	timeBeginPeriod(3);

	PROCESS_INFORMATION procinfo;
	STARTUPINFO startupinfo;
	ZeroMemory(&startupinfo,sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);

	HRESULT hr;
	
	if (!IsDebuggerPresent()) {
		SECURITY_ATTRIBUTES sec;
		ZeroMemory(&sec,sizeof(sec));
		sec.bInheritHandle = TRUE;

		TCHAR logfile[MAX_PATH];
		if (SUCCEEDED(hr = SHGetFolderPathAndSubDir(NULL,CSIDL_MYDOCUMENTS,NULL,SHGFP_TYPE_CURRENT,TEXT("My Games\\Skyrim"), logfile))) {
			PathAppend(logfile, TEXT("Skyrim4GB.log"));
			startupinfo.hStdOutput = startupinfo.hStdError = CreateFile(logfile,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sec,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
			startupinfo.dwFlags |= STARTF_USESTDHANDLES;
		}
	}
	else {
		AllocConsole();
	}

	if (CreateProcess(setbit?TEXT("TESV.exe.4gb"):TEXT("TESV.exe"), TEXT("TESV.exe"), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startupinfo,  &procinfo))
	{
		if (startupinfo.dwFlags & STARTF_USESTDHANDLES) {
			CloseHandle(startupinfo.hStdOutput);
			if (startupinfo.hStdError != startupinfo.hStdOutput)
				CloseHandle(startupinfo.hStdError);
		}
#ifdef UNICODE
		LPBYTE addr_load_lib = (LPBYTE) GetProcAddress(GetModuleHandle(TEXT("KERNEL32")),"LoadLibraryW");
#else
		LPBYTE addr_load_lib = (LPBYTE) GetProcAddress(GetModuleHandle(TEXT("KERNEL32")),"LoadLibraryA");
#endif

		const TCHAR dllname[] = TEXT("skyrim4gb_helper.dll");
		LPBYTE ADDR_name = (LPBYTE) VirtualAllocEx(procinfo.hProcess,0, size*sizeof(TCHAR)+sizeof(dllname), MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

		SIZE_T num_written;

		if(size) WriteProcessMemory(procinfo.hProcess,ADDR_name,this_name,size*sizeof(TCHAR),&num_written);
		WriteProcessMemory(procinfo.hProcess,ADDR_name+size*sizeof(TCHAR),dllname,sizeof(dllname),&num_written);

		// Create a thread to inject the dll... and wait till it's finished
		HANDLE hook_thread = CreateRemoteThread(procinfo.hProcess,NULL,32768,(LPTHREAD_START_ROUTINE)addr_load_lib, ADDR_name, 0, NULL);
		WaitForSingleObject(hook_thread,INFINITE);
		DWORD result;
		GetExitCodeThread(hook_thread, &result);
		CloseHandle(hook_thread);

		// Release our resources
		VirtualFreeEx(procinfo.hProcess,ADDR_name,0,MEM_RELEASE);

		if (setbit)
		{
			MEMORY_BASIC_INFORMATION  meminfo;

			SIZE_T buffersize = VirtualQuery((LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));

			// If this exe doesnt get a larger than normal address space, don't check the game itself
			if (buffersize != 0)
			{
				buffersize = VirtualQueryEx(procinfo.hProcess,(LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));
				if (buffersize == 0) ShowError(TEXT("Error while checking Address Space"));
			}
		}

		// Resume the main thread and then leave!
		ResumeThread(procinfo.hThread);
		CloseHandle(procinfo.hThread);

		if (dialog) PostMessage(dialog,WM_USER,0,0);

		WaitForSingleObject(procinfo.hProcess,INFINITE);
		CloseHandle(procinfo.hProcess);
	}
	else
	{
		ShowError(TEXT("Failed to start Skyrim"));
	}

	timeEndPeriod(3);

	if (dialog) PostMessage(dialog,WM_USER,0,0);

//	DeleteFile(TEXT("TESV.exe.4gb"));

	return 0;
}

