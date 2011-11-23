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

void LogMessageBox(__in LPCTSTR lpText, __in  LPCTSTR lpCaption, __in  UINT uType)
{
	Write("    Loader: ");
	Write(lpCaption);
	Write(" - ");
	WriteLine(lpText);

	MessageBox(0,lpText,lpCaption,uType);
}

HWND dialog = 0;

int Change4GBValue(LPVOID baseaddress, int set, DWORD size)
{
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>( baseaddress );
	if( pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{ 
		WriteLine("    Loader: pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE");
		return -1; 
	}

	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	    (PBYTE)baseaddress + pDOSHeader->e_lfanew );

	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{ 
		WriteLine("    Loader: pNTHeader->Signature != IMAGE_NT_SIGNATURE");
		return -1; 
	}

	PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>( 
		(PBYTE)&pNTHeader->FileHeader );

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		(PBYTE)&pNTHeader->OptionalHeader );

	/////////////////////////////////////////////////////////////
	if( IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic )
	{ 
		WriteLine("    Loader: IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic");
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

	static bool checked = false;

	// Caclulate the checksum...
	if (!checked) {


		LPWORD ptr = (LPWORD) baseaddress;
		LPWORD endcs = (LPWORD)&pOptionalHeader->CheckSum;
		LPWORD endch = &pFileHeader->Characteristics;
		LPWORD end = (LPWORD)&pOptionalHeader->CheckSum;
		DWORD checksum = 0;

		for (int i = 0; i < 2; i++) {

			int phase = (endcs>endch)^i;

			if (phase == 0) end = endcs;
			else end = endch;

			while (ptr != end) {
				checksum = (checksum&0xFFFF) + *ptr++ + (checksum>>16);
			}

			if (phase == 0) {
				checksum = (checksum&0xFFFF) + (checksum>>16);
				checksum = (checksum&0xFFFF) + (checksum>>16);
				ptr+=2;
			}
			else if (set != -2) {
				checksum = (checksum&0xFFFF) + (*ptr++&~IMAGE_FILE_LARGE_ADDRESS_AWARE) + (checksum>>16);
			}
			else {
				checksum = (checksum&0xFFFF) + *ptr++ + (checksum>>16);
			}
		}

		end = (LPWORD)baseaddress + size/2;
		while (ptr != end) {
			checksum = (checksum&0xFFFF) + *ptr++ + (checksum>>16);
		}
		checksum = (checksum&0xFFFF) + size + (checksum>>16);

		if (checksum != pOptionalHeader->CheckSum) {
			WriteLine("    Loader: checksum != pOptionalHeader->CheckSum");
			return -1;
		}
	}

	return (ret & IMAGE_FILE_LARGE_ADDRESS_AWARE)!=0;
}

void ShowError(LPTSTR title,DWORD error=GetLastError())
{
	LPVOID lpMsgBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR) &lpMsgBuf,
		0, NULL );

	if (dialog) PostMessage(dialog,WM_USER,0,0);
	LogMessageBox((LPTSTR) lpMsgBuf, title, MB_ICONERROR); 
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

	int original = Change4GBValue(pBaseAddress,set,GetFileSize(hFile,NULL));

	UnmapViewOfFile(pBaseAddress);
	CloseHandle(hFileMapping); 

	if (newatts && set>=0) SetFileTime(hFile,&newatts->ftCreationTime,&newatts->ftLastAccessTime,&newatts->ftLastWriteTime);
	CloseHandle(hFile); 

	if (original == -1) return -2;

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

	HRESULT hr;
	PROCESS_INFORMATION procinfo;
	STARTUPINFO startupinfo;
	ZeroMemory(&startupinfo,sizeof(startupinfo));
	startupinfo.cb = sizeof(startupinfo);

	if (!IsDebuggerPresent()) {
		SECURITY_ATTRIBUTES sec;
		ZeroMemory(&sec,sizeof(sec));
		sec.bInheritHandle = TRUE;

		TCHAR logfile[MAX_PATH];
		if (SUCCEEDED(hr = SHGetFolderPathAndSubDir(NULL,CSIDL_MYDOCUMENTS,NULL,SHGFP_TYPE_CURRENT,TEXT("My Games\\Skyrim"), logfile))) {
			PathAppend(logfile, TEXT("Skyrim4GB.log"));
			hOutput = hError = startupinfo.hStdOutput = startupinfo.hStdError = CreateFile(logfile,GENERIC_WRITE,FILE_SHARE_READ,&sec,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
			startupinfo.dwFlags |= STARTF_USESTDHANDLES;

			// Write byte order marks...
			Write("\xEF\xBB\xBF",hOutput);
		}
	}
	else {
		AllocConsole();
		hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		hError = GetStdHandle(STD_ERROR_HANDLE);
	}

	OSVERSIONINFO osinfo;
	osinfo.dwOSVersionInfoSize = sizeof(osinfo);
	Write("    Loader: Getting windows version");
	if (GetVersionEx(&osinfo)) {
		Write(" - ");
		Write((int) osinfo.dwMajorVersion);
		Write(".");
		Write((int) osinfo.dwMinorVersion);
		Write(".");
		Write((int) osinfo.dwBuildNumber);
		Write(" ");
		WriteLine(osinfo.szCSDVersion);
	}
	else {
		WriteLine(" - Failed");
	}

	TCHAR this_name[MAX_PATH];
	Write("    Loader: Getting executable name");

	if (!GetModuleFileName(GetModuleHandle(NULL),this_name,MAX_PATH)) {
		WriteLine(" - Failed");
	}
	else {
		Write(" - ");
		WriteLine(this_name);
	}

	// Get our name
	TCHAR *slash = FindLast(this_name,'/');
	TCHAR *backslash = FindLast(this_name,'\\');
	INT_PTR dll_path_size = 0;
	if (backslash && (!slash || backslash < slash)) dll_path_size = 1 + backslash - this_name;
	else if (slash) dll_path_size = 1 + slash - this_name;

	// want to make sure that we aren't called skyrim and going to cause an infinite loop
	TCHAR *dot = FindFirst(this_name+dll_path_size, '.');
	if (!dot) {
		for (dot = this_name; *dot; dot++);
	}
	
	Write("    Loader: Making sure this executable is not called TESV.exe");
	if (CompareString(LOCALE_INVARIANT, NORM_IGNORECASE, this_name+dll_path_size,dot-(this_name+dll_path_size),TEXT("TESV"),4) == CSTR_EQUAL)
	{
		WriteLine(" - It is");
		if (dialog) PostMessage(dialog,WM_USER,0,0);
		LogMessageBox(TEXT("Skyrim4GB loader must not be named TESV.exe"), TEXT("Error"), MB_ICONERROR);
		return -1;
	}
	else
		WriteLine(" - It isn't");

	TCHAR skyrimpath[MAX_PATH+1] = TEXT("");
	
	HKEY regkey;

	WriteLine("    Loader: Trying to get Skyrim path from Bethesda Softworks registry key");
	Write("    Loader: Attmepting to open HKLM\\SOFTWARE\\Bethesda Softworks\\Skyrim");
	if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Bethesda Softworks\\Skyrim"),&regkey) == ERROR_SUCCESS)
	{
		WriteLine(" - Succeeded");
		DWORD type;
		Write("    Loader: Attempting to query size of \"Installed Path\" value");
		if (RegQueryValueEx(regkey,TEXT("Installed Path"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
		{
			WriteLine(" - Succeeded");
			DWORD skyrimpath_size = (MAX_PATH+1)*sizeof(TCHAR);
			Write("    Loader: Attempting to query \"Installed Path\" value");
			if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("Installed Path"),NULL,&type,(LPBYTE) skyrimpath,&skyrimpath_size) == ERROR_SUCCESS)
			{
				if (type == REG_SZ || type == REG_EXPAND_SZ)
				{
					WriteLine(" - Succeeded");
					skyrimpath[MAX_PATH] = 0;				
				}
				else
					WriteLine(" - Failed");
			}
			else
				WriteLine(" - Failed");
		}
		else
			WriteLine(" - Failed");
		RegCloseKey(regkey);
	}
	else
		WriteLine(" - Failed");

	// Attempt to get it from steam
	if (!*skyrimpath) 
	{
		WriteLine("    Loader: Trying to get Skyrim path from Steam registry key");
		Write("    Loader: Attmepting to open HKLM\\SOFTWARE\\Valve\\Steam");
		if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Valve\\Steam"),&regkey) == ERROR_SUCCESS)
		{
			WriteLine(" - Succeeded");
			DWORD type;
			Write("    Loader: Attempting to query size of \"InstallPath\" value");
			if (RegQueryValueEx(regkey,TEXT("InstallPath"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
			{
				WriteLine(" - Succeeded");
				DWORD skyrimpath_size = (MAX_PATH+1)*sizeof(TCHAR);
				Write("    Loader: Attempting to query \"InstallPath\" value");
				if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("InstallPath"),NULL,&type,(LPBYTE) skyrimpath,&skyrimpath_size) == ERROR_SUCCESS)
				{
					if (type == REG_SZ || type == REG_EXPAND_SZ)
					{
						WriteLine(" - Succeeded");
						skyrimpath[MAX_PATH] = 0;				
						PathAppend(skyrimpath,TEXT("steamapps\\common\\skyrim"));
					}
					else
						WriteLine(" - Failed");
				}
				else
					WriteLine(" - Failed");
			}
			else
				WriteLine(" - Failed");
			RegCloseKey(regkey);
		}
	}


	if (*skyrimpath) {
		Write("    Loader: Changing directory to ");
		WriteLine(skyrimpath);

		if (!SetCurrentDirectory(skyrimpath)) {
			ShowError(TEXT("Unable set current dir to Skyrim dir."));
			return -1;
		}
	}

	WriteLine("    Loader: Validating TESV.exe...");

	int res = Change4GBValue(TEXT("TESV.exe"), -2);

	if (res < 0) {
		WriteLine("    Loader: Validation Failed!");
		DeleteFile(TEXT("TESV.exe.4gb"));
		if (res == -2) {
			if (dialog) PostMessage(dialog,WM_USER,0,0);
			LogMessageBox(TEXT("TESV.exe modified -> Executable headers failed to validate.\n")
				TEXT("\n")
				TEXT("An unmodified TESV.exe is required. You should get Steam to validate your game cache and download unmodified versions of any files."), TEXT("Error"), MB_ICONERROR);
		}
		return -1;
	}
	else {
		WriteLine("    Loader: Validation passed");
	}

	WriteLine("    Loader: Getting file attributes for TESV.exe");
	WIN32_FILE_ATTRIBUTE_DATA TESV_exe_info, TESV_4gb_info;
	if (!GetFileAttributesEx(TEXT("TESV.exe"),GetFileExInfoStandard,&TESV_exe_info))
	{
		ShowError(TEXT("Unable to get file attribute for TESV.exe"));
		return -1;
	}

	bool updatereq = true;

	BOOL setbit = TRUE;

#ifdef ONLY_ON_WOW64
	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS  fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if (!fnIsWow64Process || !fnIsWow64Process(GetCurrentProcess(),&setbit)) 
		setbit = FALSE;

	if (CompareString(LOCALE_INVARIANT, NORM_IGNORECASE, this_name+dll_path_size,dot-(this_name+dll_path_size),TEXT("skyrim4gb-force"),12) == CSTR_EQUAL)
	{
		setbit = TRUE;
	}
#endif

	Write("    Loader: Checking if file attributes for TESV.exe and TESV.exe.4gb match");
	if (!GetFileAttributesEx(TEXT("TESV.exe.4gb"),GetFileExInfoStandard,&TESV_4gb_info) || 
		TESV_exe_info.ftCreationTime != TESV_4gb_info.ftCreationTime ||
		TESV_exe_info.ftLastWriteTime != TESV_4gb_info.ftLastWriteTime ||
		TESV_exe_info.nFileSizeHigh != TESV_4gb_info.nFileSizeHigh ||
		TESV_exe_info.nFileSizeLow != TESV_4gb_info.nFileSizeLow)
	{
		WriteLine(" - They didn't. Copying TESV.exe to TESV.exe.4gb");

		if (!CopyFile(TEXT("TESV.exe"),TEXT("TESV.exe.4gb"),FALSE))
		{
			ShowError(TEXT("Unable to copy TESV.exe to TESV.exe.4gb"));
			return -1;
		}
	}
	else {
		WriteLine(" - They did.");
		WriteLine("    Loader: Validating and checking status of TESV.exe.4gb...");

		res = Change4GBValue(TEXT("TESV.exe.4gb"), -1);

		// Couldn't read 4gb file or there was a validation error...
		if (res < 0) {
			// So delete the file
			DeleteFile(TEXT("TESV.exe.4gb"));

			// Exe validation error..
			if (res == -2) {
				WriteLine("    Loader: Failed to validate TESV.exe.4gb. Copying TESV.exe to TESV.exe.4gb");

				// Grab a new copy
				if (!CopyFile(TEXT("TESV.exe"),TEXT("TESV.exe.4gb"),FALSE))
				{
					ShowError(TEXT("Unable to copy TESV.exe to TESV.exe.4gb"));
					return -1;
				}
			}
			// Can't read or some other fatal issue so just quit
			else {
				return -1;
			}
		} else {
			updatereq = (res != 0) != (setbit!=FALSE);
			if (updatereq) WriteLine("    Loader: TESV.exe.4gb needs updating");
			else WriteLine("    Loader: TESV.exe.4gb seems good");
		}
	}

	if (updatereq) {
		WriteLine("    Loader: Updating LAA flag in TESV.exe.4gb as required");

		res = Change4GBValue(TEXT("TESV.exe.4gb"), (setbit!=FALSE)?1:0, &TESV_exe_info);

		if (res < 0) {
			DeleteFile(TEXT("TESV.exe.4gb"));

			if (res == -2 ) 
				LogMessageBox(TEXT("Unable to successfully create TESV.exe.4gb"), TEXT("Error"), MB_ICONERROR);

			return -1;		
		}
	}

	Write("    Loader: Looking for SteamAPPId passed on command line");

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

	if (!*commandLine) {
		WriteLine(" - Didn't find it. Using default 72850");
		commandLine = TEXT("72850");
	}
	else {
		Write(" - Found it: ");
		WriteLine(commandLine);
	}

	if (!SetEnvironmentVariable(TEXT("SteamAPPId"),commandLine))
	{
		ShowError(TEXT("Unable to set SteamAppId"));
		return -1;
	}

	timeBeginPeriod(3);

	Write("    Loader: Creating TESV.exe.4gb process");
	if (CreateProcess(setbit?TEXT("TESV.exe.4gb"):TEXT("TESV.exe"), TEXT("TESV.exe"), NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startupinfo,  &procinfo))
	{
		WriteLine(" - Succeeded");

#ifdef UNICODE
		LPBYTE addr_load_lib = (LPBYTE) GetProcAddress(GetModuleHandle(TEXT("KERNEL32")),"LoadLibraryW");
#else
		LPBYTE addr_load_lib = (LPBYTE) GetProcAddress(GetModuleHandle(TEXT("KERNEL32")),"LoadLibraryA");
#endif

		WriteLine("    Loader: Allocating memory buffer in TESV.exe.4gb procress");
		const TCHAR dllname[] = TEXT("skyrim4gb_helper.dll");
		LPBYTE ADDR_name = (LPBYTE) VirtualAllocEx(procinfo.hProcess,0, dll_path_size*sizeof(TCHAR)+sizeof(dllname), MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);

		SIZE_T num_written;

		WriteLine("    Loader: Writing helper dll name into memory buffer");
		if(dll_path_size) WriteProcessMemory(procinfo.hProcess,ADDR_name,this_name,dll_path_size*sizeof(TCHAR),&num_written);
		WriteProcessMemory(procinfo.hProcess,ADDR_name+dll_path_size*sizeof(TCHAR),dllname,sizeof(dllname),&num_written);


		// Create a thread to inject the dll... and wait till it's finished
		WriteLine("    Loader: Creating remote thread to load helper dll");
		HANDLE hook_thread = CreateRemoteThread(procinfo.hProcess,NULL,32768,(LPTHREAD_START_ROUTINE)addr_load_lib, ADDR_name, 0, NULL);
		if (hook_thread == NULL) {
			ShowError(TEXT("Failed to create Remote thread"));
		}
		else {
			WriteLine("    Loader: Waiting for remote thread to exit");
			WaitForSingleObject(hook_thread,INFINITE);
			DWORD result;
			GetExitCodeThread(hook_thread, &result);
		}
		CloseHandle(hook_thread);

		// Release our resources
		WriteLine("    Loader: Freeing memory buffer in TESV.exe.4gb process");
		VirtualFreeEx(procinfo.hProcess,ADDR_name,0,MEM_RELEASE);

		if (setbit)
		{
			Write("    Loader: Checking if LAA has any effect");
			MEMORY_BASIC_INFORMATION  meminfo;

			SIZE_T buffersize = VirtualQuery((LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));

			// If this exe doesnt get a larger than normal address space, don't check the game itself
			if (buffersize != 0)
			{
				WriteLine(" - It does.");
				Write("    Loader: Checking if LAA flag worked for TESV.exe.4gb process");

				buffersize = VirtualQueryEx(procinfo.hProcess,(LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));
				if (buffersize != 0) {
					WriteLine(" - It Did");
				}
				else {
					DWORD error = GetLastError();
					WriteLine(" - It Didn't");
					ShowError(TEXT("Error while checking Address Space"),error);
				}
			}
			else {
				WriteLine(" - It doesn't. Operating System must be 32bit without /3GB switch enabled");
			}
		}

		// Resume the main thread and then leave!
		WriteLine("    Loader: Starting main thread in TESV.exe.4gb process");
		ResumeThread(procinfo.hThread);
		CloseHandle(procinfo.hThread);

		if (dialog) PostMessage(dialog,WM_USER,0,0);

		if (IsDebuggerPresent()) {
			WriteLine("    Loader: Waiting for TESV.exe.4gb process to exit");
			WaitForSingleObject(procinfo.hProcess,INFINITE);
		}
		CloseHandle(procinfo.hProcess);
	}
	else
	{
		WriteLine(" - Failed");

		ShowError(TEXT("Failed to start Skyrim"));
	}

	timeEndPeriod(3);

	if (dialog) PostMessage(dialog,WM_USER,0,0);

//	DeleteFile(TEXT("TESV.exe.4gb"));
	WriteLine("    Loader: Exiting");

	return 0;
}

