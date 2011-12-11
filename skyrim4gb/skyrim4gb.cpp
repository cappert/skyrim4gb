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
#include <Psapi.h>
#include "injection.h"

TCHAR this_exe[MAX_PATH+1];
TCHAR this_exe_dir[MAX_PATH+1];
LPTSTR this_exe_filename;

TCHAR tesv_exe[MAX_PATH+1] = TEXT("");
TCHAR tesv_exe_dir[MAX_PATH+1] = TEXT("");
LPTSTR tesv_exe_filename;

TCHAR tesv_exe_4gb[MAX_PATH+1] = TEXT("");
TCHAR tesv_exe_4gb_dir[MAX_PATH+1] = TEXT("");
LPTSTR tesv_exe_4gb_filename;

LPTSTR launch_parameters = TEXT("");

TCHAR SteamAPPId[16] = TEXT("");

struct ExtraDLL {
	TCHAR file[MAX_PATH+1];
	ExtraDLL *next;
};
ExtraDLL *extra_dlls = 0;
ExtraDLL *extra_dlls_last = 0;

void LogMessageBox(__in LPCTSTR lpText, __in  LPCTSTR lpCaption, __in  UINT uType)
{
	Console->Write("    Loader: ")->Write(lpCaption)->Write(" - ")->WriteLine(lpText);

	MessageBox(0,lpText,lpCaption,uType);
}

HWND dialog = 0;

int Change4GBValue(LPVOID baseaddress, int set, DWORD size)
{
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>( baseaddress );
	if( pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{ 
		Console->WriteLine("    Loader: pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE");
		return -1; 
	}

	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	    (PBYTE)baseaddress + pDOSHeader->e_lfanew );

	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{ 
		Console->WriteLine("    Loader: pNTHeader->Signature != IMAGE_NT_SIGNATURE");
		return -1; 
	}

	PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>( 
		(PBYTE)&pNTHeader->FileHeader );

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		(PBYTE)&pNTHeader->OptionalHeader );

	/////////////////////////////////////////////////////////////
	if( IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic )
	{ 
		Console->WriteLine("    Loader: IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic");
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
			Console->WriteLine("    Loader: checksum != pOptionalHeader->CheckSum");
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
	HANDLE hFile = INVALID_HANDLE_VALUE;
	/////////////////////////////////////////////////////////////
	int limit = set?10:1;

	while(limit && hFile==INVALID_HANDLE_VALUE) {
		hFile = CreateFile( filename, GENERIC_READ|(set>=0?GENERIC_WRITE:0), FILE_SHARE_READ,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		if (limit-- && hFile==INVALID_HANDLE_VALUE) Sleep(1000);
	}
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

bool CheckAllFilenames()
{
	Console->Write("    Loader: Making sure original and LAA exe are not the same file");
	if (!CheckFilenames(tesv_exe, tesv_exe_4gb)) {
		Console->WriteLine(" - They are");
		LogMessageBox(TEXT("Files for original and LAA exe must be different"), TEXT("Error"), MB_ICONERROR);
		return false;
	}
	else {
		Console->WriteLine(" - They aren't");
	}

	LPTSTR exes[] = { tesv_exe, tesv_exe_4gb };

	for (int i = 0; i < sizeof(exes)/sizeof(exes[0]); i++) {

		Console->Write("    Loader: Making sure this executable is not ");
		Console->Write(exes[i]);

		if (!CheckFilenames(this_exe,exes[i]))
		{
			Console->WriteLine(" - It is");
			if (dialog) PostMessage(dialog,WM_USER,0,0);
			LogMessageBox(TEXT("Skyrim4GB loader must not be named the same as the original or LAA exe"), TEXT("Error"), MB_ICONERROR);
			return false;
		}
		else
			Console->WriteLine(" - It isn't");
	}

	return true;
}

void ParseArgument(LPTSTR &commandLine, LPTSTR result) {

	// Get the argument
	TCHAR c;
	bool quoted = false;
	while (c = *commandLine) {
		++commandLine;

		if (c == '"') {
			quoted = !quoted;
			continue;
		}
		else if (!quoted && (c == ' ' || c == '\t')) {
			break;
		}
		*result++ = c;
	}

	// Skip past whitespace at the end of the argument getting us to the start of the next one
	while (c = *commandLine)  {
		if (c != ' ' && c != '\t') break;
		++commandLine;
	}

	*result = 0;
}

void ParseCommandLine(LPTSTR commandLine) {
	LPTSTR temp = (LPTSTR) LocalAlloc(0,my_strlen(commandLine)*sizeof(TCHAR));

	// Skip path first argument (executable name - could be anything or nothing)
	ParseArgument(commandLine,temp);

	bool noskse = false;

	while (*commandLine) {
		ParseArgument(commandLine,temp);

		// Start of arguments to the launched executable
		if (!my_stricmp(temp,TEXT("--"))) {
			break;
		}
		// Path of original game executable
		else if (!my_stricmp(temp,TEXT("-exe"))) {
			if (!*commandLine) break;
			Console->Write("            exe = ");

			ParseArgument(commandLine,temp);

			my_strcpy_s(tesv_exe,temp);
			Console->WriteLine(tesv_exe);
		}
		// Path of Large Address Aware executable that gets created
		else if (!my_stricmp(temp,TEXT("-laaexe"))) {
			if (!*commandLine) break;
			Console->Write("            laaexe = ");
			ParseArgument(commandLine,temp);

			my_strcpy_s(tesv_exe_4gb,temp);
			Console->WriteLine(tesv_exe_4gb);
		}
		// Don't load skse
		else if (!my_stricmp(temp,TEXT("-noskse"))) {
			Console->WriteLine("            noskse");
			noskse = true;
		}
		else if (!my_stricmp(temp,TEXT("-extradll"))) {
			if (!*commandLine) break;
			Console->Write("            extradll = ");
			ParseArgument(commandLine,temp);

			ExtraDLL *extra_dll = (ExtraDLL *)LocalAlloc(0,sizeof(ExtraDLL));
			extra_dll->next = 0;
			my_strcpy_s(extra_dll->file,temp);
			Console->WriteLine(extra_dll->file);
			
			if (!extra_dlls_last) {
				extra_dlls_last = extra_dlls = extra_dll;
			}
			else {
				extra_dlls_last = extra_dlls_last->next = extra_dll;
			}			
		}
		// SteamAPPId
		else {
			if (!my_stricmp(temp,TEXT("-SteamAPPId"))) {
				if (!*commandLine) break;
				ParseArgument(commandLine,temp);
			}
		
			if (temp[0] && temp[0] != '-') {
				Console->Write("            SteamAPPId = ");
				my_strcpy_s(SteamAPPId,temp);
				Console->WriteLine(SteamAPPId);
			}
		}
	}

	LocalFree((HLOCAL)temp);

	if(!noskse) {
		ExtraDLL *extra_dll = (ExtraDLL *)LocalAlloc(0,sizeof(ExtraDLL));
		extra_dll->next = 0;
		my_strcpy_s(extra_dll->file,TEXT("skse_steam_loader.dll"));
			
		extra_dll->next = extra_dlls;
		extra_dlls = extra_dll;
		if (!extra_dlls_last) extra_dlls_last = extra_dll;
	}

	// Finally
	launch_parameters = commandLine;
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
			Console->h = Console->Error->h = startupinfo.hStdOutput = startupinfo.hStdError = CreateFile(logfile,GENERIC_WRITE,FILE_SHARE_READ,&sec,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,0);
			startupinfo.dwFlags |= STARTF_USESTDHANDLES;

			// Console->Write byte order marks...
			Console->Write("\xEF\xBB\xBF");
		}
	}
	else {
		AllocConsole();
		Console->h = GetStdHandle(STD_OUTPUT_HANDLE);
		Console->Error->h = GetStdHandle(STD_ERROR_HANDLE);
	}


	OSVERSIONINFO osinfo;
	osinfo.dwOSVersionInfoSize = sizeof(osinfo);
	Console->Write("    Loader: Getting windows version");
	if (GetVersionEx(&osinfo)) {
		Console->Write(" - ")->Write((int) osinfo.dwMajorVersion)
			     ->Write(".")->Write((int) osinfo.dwMinorVersion)
				 ->Write(".")->Write((int) osinfo.dwBuildNumber)
				 ->Write(" ")->WriteLine(osinfo.szCSDVersion);
	}
	else {
		Console->WriteError(" - Failed");
	}

	//
	// Parse command line
	// 

	Console->WriteLine("    Loader: Parsing Command Line...");
	ParseCommandLine(GetCommandLine());

	//
	// Loaders Executable name (and path)
	//

	Console->Write("    Loader: Getting executable name");

	if (!GetModuleFileName(GetModuleHandle(NULL),this_exe,MAX_PATH)) {
		Console->WriteLine(" - Failed");
		return false;
	}
	else {
		Console->Write(" - ");
		Console->WriteLine(this_exe);

		this_exe_filename = PathFindFileName(this_exe);

		LPTSTR src = this_exe;
		LPTSTR dst = this_exe_dir;
		while (src != this_exe_filename) *dst++ = *src++;
		*dst = 0;
	}

	//
	// Original executables name...
	//

	if (!*tesv_exe) {
		my_strcpy_s(tesv_exe,TEXT("TESV.exe"));
	}

	if (PathIsRelative(tesv_exe)) {

		HKEY regkey;

		Console->WriteLine("    Loader: Trying to get Skyrim path from Bethesda Softworks registry key");
		Console->Write("    Loader: Attmepting to open HKLM\\SOFTWARE\\Bethesda Softworks\\Skyrim");
		if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Bethesda Softworks\\Skyrim"),&regkey) == ERROR_SUCCESS)
		{
			Console->WriteLine(" - Succeeded");
			DWORD type;
			Console->Write("    Loader: Attempting to query size of \"Installed Path\" value");
			if (RegQueryValueEx(regkey,TEXT("Installed Path"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
			{
				Console->WriteLine(" - Succeeded");
				DWORD tesv_exe_dir_size = (MAX_PATH+1)*sizeof(TCHAR);
				Console->Write("    Loader: Attempting to query \"Installed Path\" value");
				if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("Installed Path"),NULL,&type,(LPBYTE) tesv_exe_dir,&tesv_exe_dir_size) == ERROR_SUCCESS)
				{
					if (type == REG_SZ || type == REG_EXPAND_SZ)
					{
						Console->WriteLine(" - Succeeded");
						tesv_exe_dir[MAX_PATH] = 0;				
					}
					else
						Console->WriteLine(" - Failed");
				}
				else
					Console->WriteLine(" - Failed");
			}
			else
				Console->WriteLine(" - Failed");
			RegCloseKey(regkey);
		}
		else
			Console->WriteLine(" - Failed");

		// Attempt to get it from steam
		if (!*tesv_exe_dir) 
		{
			Console->WriteLine("    Loader: Trying to get Skyrim path from Steam registry key");
			Console->Write("    Loader: Attmepting to open HKLM\\SOFTWARE\\Valve\\Steam");
			if (RegOpenKey(HKEY_LOCAL_MACHINE,TEXT("SOFTWARE\\Valve\\Steam"),&regkey) == ERROR_SUCCESS)
			{
				Console->WriteLine(" - Succeeded");
				DWORD type;
				Console->Write("    Loader: Attempting to query size of \"InstallPath\" value");
				if (RegQueryValueEx(regkey,TEXT("InstallPath"),NULL ,&type,NULL,NULL) == ERROR_SUCCESS)
				{
					Console->WriteLine(" - Succeeded");
					DWORD tesv_exe_dir_size = (MAX_PATH+1)*sizeof(TCHAR);
					Console->Write("    Loader: Attempting to query \"InstallPath\" value");
					if ((type == REG_SZ || type == REG_EXPAND_SZ) && RegQueryValueEx(regkey,TEXT("InstallPath"),NULL,&type,(LPBYTE) tesv_exe_dir,&tesv_exe_dir_size) == ERROR_SUCCESS)
					{
						if (type == REG_SZ || type == REG_EXPAND_SZ)
						{
							Console->WriteLine(" - Succeeded");
							tesv_exe_dir[MAX_PATH] = 0;				
							PathAppend(tesv_exe_dir,TEXT("steamapps\\common\\skyrim"));
						}
						else
							Console->WriteLine(" - Failed");
					}
					else
						Console->WriteLine(" - Failed");
				}
				else
					Console->WriteLine(" - Failed");
				RegCloseKey(regkey);
			}
		}


		if (*tesv_exe_dir) {
			TCHAR pathtemp[MAX_PATH+1];
			int i;
			for (i = 0; i < MAX_PATH; i++) {
				pathtemp[i] = tesv_exe[i];
			}
			pathtemp[i] = 0;
			PathCombine(tesv_exe,tesv_exe_dir,pathtemp);
		}
		tesv_exe_filename = PathFindFileName(tesv_exe);
	}
	else {
		tesv_exe_filename = PathFindFileName(tesv_exe);
		LPTSTR src = tesv_exe;
		LPTSTR dest = tesv_exe_dir;
		while (src != tesv_exe_filename) *dest++ = *src++;
		*dest = 0;
	}

	if (*tesv_exe_dir) {
		Console->Write("    Loader: Changing directory to ")->WriteLine(tesv_exe_dir);

		if (!SetCurrentDirectory(tesv_exe_dir)) {
			ShowError(TEXT("Unable set current dir to Skyrim dir."));
			return -1;
		}
	}

	//
	// LAA's executables name...
	//

	if (!*tesv_exe_4gb) {
		my_strcpy_s(tesv_exe_4gb,tesv_exe);
		my_strcat_s(tesv_exe_4gb,TEXT(".4gb"));
	}
	else if (PathIsRelative(tesv_exe_4gb)) {

		LPTSTR src_dir;
		if (tesv_exe_4gb[0] == '.' && (tesv_exe_4gb[1] == '/' || tesv_exe_4gb[1] == '\\'))
			src_dir = this_exe_dir;
		else
			src_dir = tesv_exe_dir;

		if (*src_dir) {
			TCHAR pathtemp[MAX_PATH+1];
			int i;
			for (i = 0; i < MAX_PATH; i++) {
				pathtemp[i] = tesv_exe_4gb[i];
			}
			pathtemp[i] = 0;
			PathCombine(tesv_exe_4gb,src_dir,pathtemp);	
		}
	}

	tesv_exe_4gb_filename = PathFindFileName(tesv_exe_4gb);
	if (!PathIsRelative(tesv_exe_4gb))
	{
		LPTSTR src = tesv_exe_4gb;
		LPTSTR dst = tesv_exe_4gb_dir;
		while (src != tesv_exe_4gb_filename) *dst++ = *src++;
		*dst = 0;
	}

	Console->Write("    Loader: Original exe is: ")->Write(tesv_exe)->WriteLine();
	Console->Write("    Loader: LAA exe is: ")->Write(tesv_exe_4gb)->WriteLine();

	Console->WriteLine("    Loader: Validating original exe...");

	int res = Change4GBValue(tesv_exe, -2);

	if (res < 0) {
		Console->WriteLine("    Loader: Validation Failed!");
		if (CheckFilenames(tesv_exe,tesv_exe_4gb)) DeleteFile(tesv_exe_4gb);
		if (res == -2) {
			if (dialog) PostMessage(dialog,WM_USER,0,0);
			LogMessageBox(TEXT("Original exe modified -> Executable headers failed to validate.\n")
				TEXT("\n")
				TEXT("An unmodified original exe is required. You should get Steam to validate your game cache and download unmodified versions of any files."), TEXT("Error"), MB_ICONERROR);
		}
		return -1;
	}
	else {
		Console->WriteLine("    Loader: Validation passed");
	}

	//
	// Checking filenames
	//
	if (!CheckAllFilenames()) {
		return -1;
	}


	Console->WriteLine("    Loader: Getting file attributes for original exe");
	WIN32_FILE_ATTRIBUTE_DATA TESV_exe_info, TESV_4gb_info;
	if (!GetFileAttributesEx(tesv_exe,GetFileExInfoStandard,&TESV_exe_info))
	{
		ShowError(TEXT("Unable to get file attribute for original exe"));
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

	Console->Write("    Loader: Checking if file attributes for original exe and LAA exe match");
	if (!GetFileAttributesEx(tesv_exe_4gb,GetFileExInfoStandard,&TESV_4gb_info) || 
		TESV_exe_info.ftCreationTime != TESV_4gb_info.ftCreationTime ||
		TESV_exe_info.ftLastWriteTime != TESV_4gb_info.ftLastWriteTime ||
		TESV_exe_info.nFileSizeHigh != TESV_4gb_info.nFileSizeHigh ||
		TESV_exe_info.nFileSizeLow != TESV_4gb_info.nFileSizeLow)
	{
		Console->Write(" - They didn't. Copying ")->Write(tesv_exe)->Write(" to ")->Write(tesv_exe_4gb)->WriteLine();

		if (*tesv_exe_4gb_dir) CreateDirectory(tesv_exe_4gb_dir,NULL);
		if (!CopyFile(tesv_exe,tesv_exe_4gb,FALSE))
		{
			ShowError(TEXT("Unable to copy file."));
			return -1;
		}
	}
	else {
		Console->WriteLine(" - They did.");
		Console->Write("    Loader: Validating and checking status of ")->Write(tesv_exe_4gb)->Write("...")->WriteLine();

		res = Change4GBValue(tesv_exe_4gb, -1);

		// Couldn't read 4gb file or there was a validation error...
		if (res < 0) {
			// So delete the file
			DeleteFile(tesv_exe_4gb);

			// Exe validation error..
			if (res == -2) {
				Console->Write("    Loader: File failed to validate. Copying ")->Write(tesv_exe)->Write(" to ")->Write(tesv_exe_4gb)->WriteLine();

				if (*tesv_exe_4gb_dir) CreateDirectory(tesv_exe_4gb_dir,NULL);

				// Grab a new copy
				if (!CopyFile(tesv_exe,tesv_exe_4gb,FALSE))
				{
					ShowError(TEXT("Unable to copy file."));
					return -1;
				}
			}
			// Can't read or some other fatal issue so just quit
			else {
				return -1;
			}
		} else {
			updatereq = (res != 0) != (setbit!=FALSE);
			if (updatereq) Console->WriteLine("    Loader: needs updating");
			else Console->WriteLine("    Loader: seems good");
		}
	}

	if (updatereq) {
		Console->WriteLine("    Loader: Updating LAA flag as required");

		res = Change4GBValue(tesv_exe_4gb, (setbit!=FALSE)?1:0, &TESV_exe_info);

		if (res < 0) {
			DeleteFile(tesv_exe_4gb);

			if (res == -2 ) 
				LogMessageBox(TEXT("Unable to successfully set LAA flag"), TEXT("Error"), MB_ICONERROR);

			return -1;		
		}
	}

	// should get it from steam\config\config.vdf

	// Find the argument, if it exists

	Console->Write("    Loader: Setting SteamAPPId environment variable to ");
	if (!*SteamAPPId) {
		Console->WriteLine("72850 (default)");
		my_strcpy_s(SteamAPPId,TEXT("72850"));
	}
	else {
		Console->WriteLine(SteamAPPId);
	}

	if (!SetEnvironmentVariable(TEXT("SteamAPPId"),SteamAPPId))
	{
		ShowError(TEXT("Unable to set SteamAPPId"));
		return -1;
	}

	timeBeginPeriod(3);

	size_t commandLineSize = (my_strlen(tesv_exe)+my_strlen(launch_parameters)+1)*sizeof(TCHAR);
	LPTSTR commandLine = (LPTSTR) LocalAlloc(0,commandLineSize );
	my_strcpy_s(commandLine, commandLineSize, tesv_exe);
	my_strcat_s(commandLine, commandLineSize, launch_parameters);

	Console->Write("    Loader: Creating process: \"")->Write(tesv_exe_4gb)->Write("\" ")->Write(launch_parameters)->WriteLine();
	if (CreateProcess(setbit?tesv_exe_4gb:tesv_exe, commandLine, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &startupinfo,  &procinfo))
	{
		Console->Write("    Loader: Allocating memory buffer in child procress");
		DWORD_PTR ADDR_buffer = (DWORD_PTR) VirtualAllocEx(procinfo.hProcess,0, 65536, MEM_COMMIT|MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE);
		if (ADDR_buffer == 0) {
			ShowError(TEXT("Error allocating memory in child process"));
			goto FAILURE; 
		}
		else {
			Console->Write(" - Success. Buffer at ")->Write(ADDR_buffer)->WriteLine();
		}
		SIZE_T num_written;

		// Work around ASLR
		HMODULE thisKernel32 = GetModuleHandle(TEXT("KERNEL32"));
		MODULEINFO thisKernel32Info;
		TCHAR thisKernel32Filename[MAX_PATH+1];
		HMODULE *otherModules = 0;
		HMODULE otherKernel32 = 0;
		MODULEINFO otherKernel32Info;
		TCHAR otherKernel32Filename[MAX_PATH+1];
		DWORD otherModuleCount = 0;
		DWORD needed = 0;

		LPVOID ADDR_write = 0;
		SIZE_T SIZE_write = 0;

		//
		// Get Kernel Information from this process
		//

		Console->WriteLine("    Loader: Getting handle to Kernel32");
		if (!thisKernel32 ) {
			ShowError(TEXT("Error getting handle to Kernel32"));
			goto FAILURE; 
		}

		Console->WriteLine("    Loader: Getting filename of Kernel32");
		if (!GetModuleFileName(thisKernel32,thisKernel32Filename,sizeof(thisKernel32Filename))) {
			ShowError(TEXT("Error getting filename of Kernel32"));
			goto FAILURE; 
		}

		Console->WriteLine("    Loader: Getting module information for Kernel32");
		if (!GetModuleInformation(GetCurrentProcess(),thisKernel32,&thisKernel32Info,sizeof(thisKernel32Info))) {
			ShowError(TEXT("Error getting module information for Kernel32"));
			goto FAILURE; 
		}

		//
		// Get Kernel32 Information from remote process
		// 
		Console->WriteLine("    Loader: Creating remote thread to initialize libraries");

		LPVOID code;
		DWORD code_size;

		code_size = Injection::GetStubCode(code);

		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write=(LPVOID)(ADDR_buffer),code,SIZE_write=code_size,&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		HANDLE remote_thread = CreateRemoteThread(procinfo.hProcess,NULL,32768,(LPTHREAD_START_ROUTINE)ADDR_buffer, 0, 0, NULL);
		if (remote_thread == NULL) {
			Console->WriteError(TEXT("    Loader: Failed to create Remote thread"));
			goto INFO_FAILURE; 
		}
		else {
			Console->WriteLine("    Loader: Waiting for remote thread to exit");
			WaitForSingleObject(remote_thread,INFINITE);
			DWORD result;
			GetExitCodeThread(remote_thread, &result);
			CloseHandle(remote_thread);

			if (result != 0) {
				Console->Write(TEXT("    Loader: Remote thread exited with unexpected return value 0x"));
				Console->WriteLine((DWORD_PTR) result);
			}
		}

		Console->WriteLine("    Loader: Getting number of modules loaded in child process");
		if (!EnumProcessModules(procinfo.hProcess,&otherKernel32, sizeof(HMODULE), &needed )) {
			Console->WriteError(TEXT("    Loader:Error getting number of modules loadeded in child process"));
			goto INFO_FAILURE; 
		}

		otherKernel32 = 0;
		otherModuleCount = needed;
		Console->WriteLine("    Loader: Getting handles to modules loaded in child process");
		otherModules = (HMODULE*) LocalAlloc(LMEM_FIXED,otherModuleCount);
		for (;;) {

			if (!EnumProcessModules(procinfo.hProcess, otherModules, otherModuleCount, &needed )) {
				ShowError(TEXT("    Loader:Error getting handles to modules loaded in child process"));
				goto INFO_FAILURE; 
			}

			if (otherModuleCount <= needed) {
				otherModuleCount = needed;
				break;
			}

			Console->WriteLine("    Loader: Buffer was too small - trying again with a larger buffer");
			otherModuleCount = needed;
			otherModules = (HMODULE*)LocalReAlloc((HLOCAL)otherModules,otherModuleCount,0);
		}

		Console->WriteLine("    Loader: Looking for handle to Kernel32 in module handle list from child process");
		for (DWORD i = 0; i < otherModuleCount/sizeof(HMODULE); i++) {

			if (!GetModuleFileNameEx(procinfo.hProcess,otherModules[i],otherKernel32Filename,MAX_PATH+1)) {
				Console->WriteError("    Loader: Failed to get module filename of a module in the child process");
			}

			if (CompareString(LOCALE_INVARIANT, NORM_IGNORECASE, thisKernel32Filename,-1,otherKernel32Filename,-1) != CSTR_EQUAL) {
				continue;
			}
	

			if (!GetModuleInformation(procinfo.hProcess,otherKernel32 = otherModules[i],&otherKernel32Info, sizeof(otherKernel32Info))) {
				Console->WriteError(TEXT("    Loader:Error getting module information of Kernel32 in child process"));
				goto INFO_FAILURE;
			}
			break;
		}
		
		if (!otherKernel32) {
INFO_FAILURE:
			Console->WriteLine("    Loader: Couldn't find handle to Kernel32 in child process. Assuming its the same as this one");
			otherKernel32Info = thisKernel32Info;
		}

		//
		// Inject code to load helper into remote process
		//
		Console->WriteLine("    Loader: Injecting dll loader code into child process.");

		code_size = Injection::GetInjectionCode(code);

		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write=(LPVOID)(ADDR_buffer),code,SIZE_write=code_size,&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		DWORD_PTR ADDR_injection = ADDR_buffer+num_written;
		Injection injection;
		const TCHAR szDllName[] = TEXT("skyrim4gb_helper.dll");
		const CHAR szFuncName[] = "_CompleteInjection@4";

		DWORD_PTR addr_diff =  (DWORD_PTR) otherKernel32Info.lpBaseOfDll - (DWORD_PTR) thisKernel32Info.lpBaseOfDll;

#ifdef UNICODE
		*(DWORD_PTR*)&injection.LoadLibrary = (DWORD_PTR) GetProcAddress(thisKernel32,"LoadLibraryW") + addr_diff;
#else
		*(DWORD_PTR*)&injection.LoadLibrary = (DWORD_PTR) GetProcAddress(thisKernel32,"LoadLibraryA") + addr_diff;
#endif

		*(DWORD_PTR*)&injection.GetProcAddress = (DWORD_PTR) GetProcAddress(thisKernel32,"GetProcAddress") + addr_diff;

		*(DWORD_PTR*)&injection.GetLastError = (DWORD_PTR) GetProcAddress(thisKernel32,"GetLastError") + addr_diff;

		SIZE_T dll_path_size = this_exe_filename - this_exe;

		SIZE_T tesv_exe_size = my_strlen(tesv_exe)+1;

		injection.ADDR_buffer = (LPVOID)(ADDR_buffer);
		injection.szDllName = LPTSTR(ADDR_injection+sizeof(Injection));
		injection.szFuncName = (LPSTR)(injection.szDllName+dll_path_size+sizeof(szDllName)/sizeof(TCHAR));
		injection.szOriginalName = (LPTSTR)(injection.szFuncName+sizeof(szFuncName));
		injection.szExtraDLLs = (LPTSTR)(injection.szOriginalName+tesv_exe_size);

		Console->WriteLine("    Loader: Writing injection data into child process.");

		if (!WriteProcessMemory(procinfo.hProcess, ADDR_write=(LPVOID)ADDR_injection, &injection, SIZE_write=sizeof(Injection), &num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		if (dll_path_size && !WriteProcessMemory(procinfo.hProcess,ADDR_write=injection.szDllName,this_exe,SIZE_write=dll_path_size*sizeof(TCHAR),&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write=injection.szDllName+dll_path_size,szDllName,SIZE_write=sizeof(szDllName),&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}
			
		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write=injection.szFuncName,szFuncName,SIZE_write=sizeof(szFuncName),&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write=injection.szOriginalName,tesv_exe,SIZE_write=tesv_exe_size*sizeof(TCHAR),&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}

		ADDR_write = (LPBYTE)ADDR_write + SIZE_write;
		for (ExtraDLL *extra_dll = extra_dlls; extra_dll != 0; extra_dll = extra_dll->next) {
			if (!WriteProcessMemory(procinfo.hProcess,ADDR_write,extra_dll->file,SIZE_write=(my_strlen(extra_dll->file)+1)*sizeof(TCHAR),&num_written)) {
				goto WRITE_MEMORY_FAILURE; 
			}
			ADDR_write = (LPBYTE)ADDR_write + SIZE_write;
		}
		if (!WriteProcessMemory(procinfo.hProcess,ADDR_write,TEXT(""),SIZE_write=sizeof(TCHAR),&num_written)) {
			goto WRITE_MEMORY_FAILURE; 
		}
		// Create a thread to inject the dll... and wait till it's finished
		Console->WriteLine("    Loader: Creating remote thread to load helper dll");
		remote_thread = CreateRemoteThread(procinfo.hProcess,NULL,32768,(LPTHREAD_START_ROUTINE)ADDR_buffer, (LPVOID)ADDR_injection, 0, NULL);
		if (remote_thread == NULL) {
			ShowError(TEXT("Failed to create Remote thread"));
			goto FAILURE;
		}
		else {
			Console->WriteLine("    Loader: Waiting for remote thread to exit");
			WaitForSingleObject(remote_thread,INFINITE);
			DWORD result;
			GetExitCodeThread(remote_thread, &result);
			if (result != ERROR_SUCCESS) {
				ShowError(TEXT("Error while injecting helper into remote thread."),result);
			}
		}
		CloseHandle(remote_thread);

		if (setbit)
		{
			Console->Write("    Loader: Checking if LAA has any effect");
			MEMORY_BASIC_INFORMATION  meminfo;

			SIZE_T buffersize = VirtualQuery((LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));

			// If this exe doesnt get a larger than normal address space, don't check the game itself
			if (buffersize != 0)
			{
				Console->WriteLine(" - It does.");
				Console->Write("    Loader: Checking if LAA flag worked for child process");

				buffersize = VirtualQueryEx(procinfo.hProcess,(LPVOID)(1UL<<31),&meminfo,sizeof(meminfo));
				if (buffersize != 0) {
					Console->WriteLine(" - It Did");
				}
				else {
					DWORD error = GetLastError();
					Console->WriteLine(" - It Didn't");
					ShowError(TEXT("Error while checking Address Space"),error);
				}
			}
			else {
				Console->WriteLine(" - It doesn't. Operating System must be 32bit without /3GB switch enabled");
			}
		}

		// Resume the main thread and then leave!
		Console->WriteLine("    Loader: Starting main thread in child process");
		ResumeThread(procinfo.hThread);
		CloseHandle(procinfo.hThread);

		if (dialog) PostMessage(dialog,WM_USER,0,0);

		if (IsDebuggerPresent()) {
			Console->WriteLine("    Loader: Waiting for child process to exit");
			WaitForSingleObject(procinfo.hProcess,INFINITE);
		}
		CloseHandle(procinfo.hProcess);

		res = 0;
		goto FINISH;

WRITE_MEMORY_FAILURE:
		{
			DWORD error = GetLastError();
			Console->Write("Failed to write 0x")
					->Write((DWORD_PTR)SIZE_write)
					->Write(" bytes at 0x")
					->Write(ADDR_write)
					->Write(" in child process. ")
					->WriteError(error);
			ShowError(TEXT("Failed to write to memory of child process"),error);
		}

FAILURE:

		TerminateProcess(procinfo.hProcess,-1);
		CloseHandle(procinfo.hThread);
		CloseHandle(procinfo.hProcess);
		res = -1;
FINISH:
		;
	}
	else
	{
		DWORD error = GetLastError();
		Console->WriteLine(" - Failed");
		ShowError(TEXT("Failed to start Skyrim"),error);
		res = -1;
	}

	timeEndPeriod(3);

	if (dialog) PostMessage(dialog,WM_USER,0,0);

//	DeleteFile(tesv_exe_4gb);
	Console->WriteLine("    Loader: Exiting");

	return res;
}

