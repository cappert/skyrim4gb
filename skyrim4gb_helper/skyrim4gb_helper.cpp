/*
SKyrim 4GB Helper DLL
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
#include "injection.h"

#ifdef _MANAGED
#pragma managed(push, off)
#endif

HMODULE executable;
MODULEINFO executable_info;
TCHAR exe_filename[MAX_PATH];

static Injection *injection = 0;

// This is now a stub as the loader now does significantly more compliated 
// stuff now. The thread isn't created at LoadLibrary any more. Code that calls
// LoadLibrary, GetProcessAddress and the new CompleteInjection function is 
// injected into the processes address space and that thread is created at 
// that code. 
extern "C" BOOL WINAPI _DllMainCRTStartup( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch(ul_reason_for_call)	
	{
    case DLL_PROCESS_ATTACH:
      //  For optimization.
      DisableThreadLibraryCalls( hModule );
      break;

	case DLL_PROCESS_DETACH:
		// Release our resources
		if (injection) {
			VirtualFree(injection->ADDR_buffer,0,MEM_RELEASE);
			injection = 0;
		}
		break;
	}

    return TRUE;
}

FARPROC WINAPI GetProcAddressWrap(
  __in  HMODULE hModule,
  __in  LPCSTR lpProcName,
  __in  LPCSTR lpModuleName
)
{
	FARPROC proc = GetProcAddress(hModule,lpProcName);
	if (!proc) {
		DWORD error = GetLastError();
		Console->Write("Failed to get Address of function ")->Write(lpProcName)
			   ->Write(" in ")->Write(lpModuleName)
			   ->Write(" -> ")->WriteError(error);
	}
	return proc;
}

int Change4GBValue(LPVOID baseaddress, bool set)
{
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>( baseaddress );
	if( pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{ 
		Console->WriteLine("pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE");
		return -1; 
	}

	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	    (PBYTE)baseaddress + pDOSHeader->e_lfanew );

	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{ 
		Console->WriteLine("pNTHeader->Signature != IMAGE_NT_SIGNATURE");
		return -1; 
	}

	PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>( 
		(PBYTE)&pNTHeader->FileHeader );

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		(PBYTE)&pNTHeader->OptionalHeader );

	/////////////////////////////////////////////////////////////
	if( IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic )
	{ 
		Console->WriteLine("IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic");
		return -1; 
	}

	int ret = pFileHeader->Characteristics;

	DWORD old;
	if (!VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), PAGE_READWRITE, &old)) {
		DWORD error = GetLastError();
		Console->WriteLine("VirtualProtect failed while attempting to set page readwrite")->WriteError(error);
		return -1;
	}

	if (set)
		pFileHeader->Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	else
		pFileHeader->Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;

	DWORD oldold;
	if (!VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), old, &oldold)) {
		DWORD error = GetLastError();
		Console->WriteLine("VirtualProtect failed while attempting to reset page protection")->WriteError(error);
		return -2;
	}

	return ret;
}


REDIRECTABLE_FUNCTION_EX(DWORD,WINAPI,GetModuleFileNameA,(__in_opt HMODULE hModule, __out LPSTR lpFilename, __in DWORD nSize))
{
	if (hModule == executable || hModule == NULL) {
		if (nSize) {
			INT codepage = AreFileApisANSI()?CP_ACP:CP_OEMCP;

			int res = WideCharToMultiByte(codepage,0,injection->szOriginalName,-1,0,0,NULL,NULL);

			LPSTR conveted = (LPSTR) LocalAlloc(LMEM_FIXED,res);
			res = WideCharToMultiByte(codepage,0,injection->szOriginalName,-1,conveted,res,NULL,NULL);

			for (int i = 0 ; i < res && i < nSize; i++)
				lpFilename[i] = conveted[i];
			lpFilename[nSize-1] = 0;

			LocalFree((HLOCAL) conveted);

			if (res > nSize) {
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return nSize;			
			}
			return res-1;
		}
		else {
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return 0;
		}
	}
	else {
		return GetModuleFileNameA_o(hModule, lpFilename, nSize);

	}
}
REDIRECTABLE_FUNCTION_EX(DWORD,WINAPI,GetModuleFileNameW,(__in_opt HMODULE hModule, __out LPWSTR lpFilename, __in DWORD nSize))
{
	DWORD res = GetModuleFileNameW_o(hModule, lpFilename, nSize);

	if (hModule == executable || hModule == NULL) {
		if (res) {
			if (res >= 8 && !my_stricmp(&exe_filename[res-8],TEXT(".exe.4gb"))) 
			{
				res-=4;
				if (lpFilename) lpFilename[res] = 0;
			}
		}
	}

	return res;
}


REDIRECTABLE_FUNCTION_EX(HANDLE,WINAPI,CreateFileA,(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile))
{
	static int allow_output = 1;
	if (allow_output)
	{
		Console->Write("CreateFile: ");
		Console->Write(lpFileName);
	}

	int len = 0;
	CHAR new_filename[MAX_PATH+1];
	while (len < MAX_PATH && (new_filename[len] = lpFileName[len]) != 0) ++len;

	if (len == MAX_PATH) new_filename[MAX_PATH+1] = 0;

	if (len >= 12 && !my_stricmp(&lpFileName[len-8],".exe.4gb")) 
	{
		new_filename[len-4] = 0;
		lpFileName = new_filename;

		if (!allow_output)
		{
			Console->Write("CreateFile: ");
			Console->Write(lpFileName);
		}
		Console->Write(" -> ");
		Console->Write(lpFileName);
		allow_output=-1;
	}


	HANDLE result = CreateFileA_o(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);

	if (result == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError(); 

		if (!allow_output) {
			Console->Write("CreateFile: ")->Write(lpFileName);
		}
		Console->Write(" - Failed -> ")->WriteError(error);

		if (allow_output==-1) allow_output = 0;
	}

	if (allow_output==-1) {
		Console->WriteLine();
		allow_output=0;
	}

	return result;
}

#if 0
#ifndef USE_THREADED_GETTICKCOUNT
#include <mmsystem.h>
REDIRECTABLE_FUNCTION_EX(DWORD,WINAPI,GetTickCount,())
{
	return timeGetTime();
}

#else
volatile DWORD counter = 0;

REDIRECTABLE_FUNCTION_EX(DWORD,WINAPI,GetTickCount,())
{
	return counter;
}

DWORD CALLBACK TimerThread(LPVOID)
{
	double freq;
	double start;

	SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_TIME_CRITICAL);

	for (int i = 0; i < 32; i++)
		if (SetThreadAffinityMask(GetCurrentThread(),1<<i) != 0) break;

	LARGE_INTEGER s,f;
	QueryPerformanceCounter(&s);	
	QueryPerformanceFrequency(&f);

	start = s.QuadPart;
	freq = f.QuadPart;
	start -= (GetTickCount()*freq)/1000;

	HMODULE Kernel32 = GetModuleHandle(TEXT("KERNEL32"));
	REDIRECT_FUNCTION(Kernel32,GetTickCount,5);

	for(;;)
	{
		LARGE_INTEGER c;
		QueryPerformanceCounter(&c);	

		double count = c.QuadPart;
		count -= start;

		counter = (DWORD)((count*1000.0)/freq);

		Sleep(2);
	}
}
#endif
#endif


extern "C" __declspec(dllexport) INT WINAPI CompleteInjection(Injection *injection)
{
	if (::injection) return -1;
	::injection = injection;
	executable = GetModuleHandle(NULL);
	GetModuleInformation(GetCurrentProcess(),executable,&executable_info,sizeof(executable_info));

	GetModuleFileName(executable,exe_filename,MAX_PATH);
	//MessageBox(0,exe_filename,TEXT("Attach Debugger"),MB_OK);

	//AllocConsole();
	if (AttachConsole(ATTACH_PARENT_PROCESS)) {
		MessageBox(0,exe_filename,TEXT("Attach Debugger?"),MB_OK);
	}
	Console->h = GetStdHandle(STD_OUTPUT_HANDLE);
	Console->Error->h = GetStdHandle(STD_ERROR_HANDLE);

	// Console->Write byte order marks...
	if (Console->h && GetFileType(Console->h) == FILE_TYPE_DISK) {
		LONG high = 0;
		if (SetFilePointer(Console->h,0,&high,FILE_CURRENT) == 0 && high == 0)
			Console->Write("\xEF\xBB\xBF");
	}
	if (Console->Error->h && GetFileType(Console->Error->h) == FILE_TYPE_DISK) {
		LONG high = 0;
		if (SetFilePointer(Console->Error->h,0,&high,FILE_CURRENT) == 0 && high == 0)
			Console->Error->Write("\xEF\xBB\xBF");
	}

	Console->WriteLine("skyrim4gb_helper: successfully injected");

	Console->Write("Executable filename: ")->WriteLine(exe_filename);
	Console->Write("Executable address: 0x")->WriteLine((DWORD_PTR)executable_info.lpBaseOfDll);

	Console->WriteLine("Unsetting LAA Bit");
	if (Change4GBValue(executable_info.lpBaseOfDll,false) < 0) {
		Console->WriteLine("Unsetting LAA bit failed");

		if (LPVOID(executable) != LPVOID(0x4000000)) {
			Console->WriteLine("Attempting at default addresss 0x400000");

			if (Change4GBValue(LPVOID(0x4000000),false) < 0) {
				Console->WriteLine("Second attempt at unsetting LAA bit failed");
			}
		} 
	}

	Console->Write("Getting Handle to KERNEL32");
	HMODULE Kernel32 = GetModuleHandle(TEXT("KERNEL32"));
	if (Kernel32 == NULL) {
		DWORD error = GetLastError();
		Console->Write(" - Failed -> ")->WriteError(error);
	}
	else {
		Console->WriteLine(" - Succeeded");
	}

	Console->WriteLine("Redirecting GetModuleFileNameA");
	if (!REDIRECT_FUNCTION(Kernel32,GetModuleFileNameA)) {
		Console->WriteLine("Falling back to CreateFileA redirection");
		REDIRECT_FUNCTION(Kernel32,CreateFileA);
	}

#if 0
#ifndef USE_THREADED_GETTICKCOUNT
	Console->WriteLine("Redirecting GetTickCount");
	REDIRECT_FUNCTION(Kernel32,GetTickCount);
#else
	LARGE_INTEGER f;
	if (QueryPerformanceFrequency(&f))
	{
		DWORD tid;
		HANDLE thread = CreateThread(NULL,0,TimerThread,0,0,&tid);
	}
#endif
#endif
	if (injection->szExtraDLLs && *injection->szExtraDLLs) {
		Console->WriteLine("Loading additional DLLs");

		TCHAR *extra_dll = injection->szExtraDLLs;

		while (*extra_dll) {
			Console->Write("Attempting to load ")->Write(extra_dll);
			HMODULE skse = LoadLibrary(extra_dll);
			if (skse == NULL) {
				DWORD error = GetLastError();
				Console->Write(" - Failed -> ")->WriteError(error);
			}
			else {
				Console->WriteLine(" - Succeeded");
			}

			extra_dll += my_strlen(extra_dll)+1;
		}
	}

	Console->WriteLine("skyrim4gb_helper: returning from CompleteInjection");

	return ERROR_SUCCESS;
}


#ifdef _MANAGED
#pragma managed(pop)
#endif

