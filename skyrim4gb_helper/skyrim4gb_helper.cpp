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

HANDLE hOutput = 0;
HANDLE hError = 0;

#ifdef _MANAGED
#pragma managed(push, off)
#endif

void WriteLine(HANDLE h=hOutput) 
{
	if (h == 0) return;

	DWORD numwritten;
	WriteFile(h,"\r\n",2, &numwritten,0);
	FlushFileBuffers(hOutput);
}

void Write(const char *str,HANDLE h=hOutput) 
{
	if (h == 0) return;

	DWORD len = 0;
	while(str[len]) ++len;

	DWORD numwritten;
	WriteFile(h,str,len,&numwritten,0);
}

void WriteLine(const char *str, HANDLE h=hOutput) 
{
	if (h == 0) return;
	Write(str,h);
	WriteLine();
}

void Write(const wchar_t *str,HANDLE h=hOutput) 
{
	if (h == 0) return;

	DWORD numwritten;

	if (GetFileType(h) == FILE_TYPE_CHAR) {
		DWORD len = 0;
		while(str[len]) ++len;
		WriteConsole (h,str,len,&numwritten,0);
	} else {
		numwritten = WideCharToMultiByte(CP_UTF8,0,str,-1,0,0,NULL,NULL);

		LPSTR utf8 = (LPSTR) LocalAlloc(LMEM_FIXED,numwritten);
		numwritten = WideCharToMultiByte(CP_UTF8,0,str,-1,utf8,numwritten,NULL,NULL);

		WriteFile(h,utf8,numwritten-1,&numwritten,0);

		LocalFree((HLOCAL) utf8);
	}
}

void WriteLine(const wchar_t *str, HANDLE h=hOutput) 
{
	if (h == 0) return;
	Write(str,h);
	WriteLine();
}
void Write(DWORD_PTR val,HANDLE h=hOutput) 
{
	if (h == 0) return;

	char str[32];
	char *ptr = str+32;
	*--ptr=0;
	while (val) {
		int nibble = val&0xF;
		val >>= 4;

		if (nibble <= 9) *--ptr = '0' + nibble;
		else *--ptr = 'A' + nibble - 0xA;
	}

	DWORD numwritten;
	WriteFile(h,ptr,str+31-ptr,&numwritten,0);
}
void WriteLine(DWORD_PTR val,HANDLE h=hOutput) 
{
	if (h == 0) return;
	Write(val,h);
	WriteLine();
}
void Write(int val,HANDLE h=hOutput)
{
	if (h == 0) return;

	bool wasneg = val<0;
	if (wasneg) val = -val;
	char str[32];
	char *ptr = str+32;
	*--ptr=0;
	while (val) {
		*--ptr = '0' + val%10;
		val /= 10;
	}
	if (wasneg) *--ptr = '-';
	DWORD numwritten;
	WriteFile(h,ptr,str+31-ptr,&numwritten,0);
}
void WriteLine(int val,HANDLE h=hOutput)
{
	if (h == 0) return;
	Write(val,h);
	WriteLine();
}

void WriteError(DWORD error, HANDLE h=hOutput)
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

	Write((LPTSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
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
		Write("Failed to get Address of function ");
		Write(lpProcName);
		Write(" in ");
		Write(lpModuleName);
		Write(" -> ");
		WriteError(error);
	}
	return proc;
}

int Change4GBValue(LPVOID baseaddress, bool set)
{
	PIMAGE_DOS_HEADER pDOSHeader = static_cast<PIMAGE_DOS_HEADER>( baseaddress );
	if( pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE )
	{ 
		WriteLine("pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE");
		return -1; 
	}

	PIMAGE_NT_HEADERS pNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(
	    (PBYTE)baseaddress + pDOSHeader->e_lfanew );

	if(pNTHeader->Signature != IMAGE_NT_SIGNATURE )
	{ 
		WriteLine("pNTHeader->Signature != IMAGE_NT_SIGNATURE");
		return -1; 
	}

	PIMAGE_FILE_HEADER pFileHeader = reinterpret_cast<PIMAGE_FILE_HEADER>( 
		(PBYTE)&pNTHeader->FileHeader );

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(
		(PBYTE)&pNTHeader->OptionalHeader );

	/////////////////////////////////////////////////////////////
	if( IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic )
	{ 
		WriteLine("IMAGE_NT_OPTIONAL_HDR32_MAGIC != pNTHeader->OptionalHeader.Magic");
		return -1; 
	}

	int ret = pFileHeader->Characteristics;

	DWORD old;
	if (!VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), PAGE_READWRITE, &old)) {
		DWORD error = GetLastError();
		WriteLine("VirtualProtect failed while attempting to set page readwrite");
		WriteError(error);
		return -1;
	}

	if (set)
		pFileHeader->Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	else
		pFileHeader->Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;

	DWORD oldold;
	if (!VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), old, &oldold)) {
		DWORD error = GetLastError();
		WriteLine("VirtualProtect failed while attempting to reset page protection");
		WriteError(error);
		return -2;
	}

	return ret;
}

	
int mystricmp(const char *left, const char *right)
{
	while (*left && *right)
	{
		int l = *left++;
		int r = *right++;

		if (l >= 'a' && l <= 'z') l -= 0x20;
		if (r >= 'a' && r <= 'z') r -= 0x20;

		int res = l - r;
		if (res != 0) return res;
	}

	return *left - *right;
}

REDIRECTABLE_FUNCTION_EX(HANDLE,WINAPI,CreateFileA,(LPCSTR lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPSECURITY_ATTRIBUTES lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile))
{
	static int allow_output = 1;
	if (allow_output)
	{
		Write("CreateFile: ");
		Write(lpFileName);
	}

	int len = 0;
	CHAR new_filename[MAX_PATH+1];
	while (len < MAX_PATH && (new_filename[len] = lpFileName[len]) != 0) ++len;

	if (len == MAX_PATH) new_filename[MAX_PATH+1] = 0;

	if (len >= 12 && !mystricmp(&lpFileName[len-8],".exe.4gb")) 
	{
		new_filename[len-4] = 0;
		lpFileName = new_filename;

		if (!allow_output)
		{
			Write("CreateFile: ");
			Write(lpFileName);
		}
		Write(" -> ");
		Write(lpFileName);
		allow_output=-1;
	}


	HANDLE result = CreateFileA_o(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);

	if (result == INVALID_HANDLE_VALUE) {
		DWORD error = GetLastError(); 

		if (!allow_output) {
			Write("CreateFile: ");
			Write(lpFileName);
		}
		Write(" - Failed -> ");
		WriteError(error);

		if (allow_output==-1) allow_output = 0;
	}

	if (allow_output==-1) {
		WriteLine();
		allow_output=0;
	}

	return result;
}

void DwordToString(DWORD num, char string[16])
{
	int count = 0;
	DWORD t = num;

	while (t)
	{
		count++;
		t /= 10;				
	}

	if (count == 0)
	{
		string[0] = '0';
		string[1] = 0;
	}
	else
	{
		string[count] = 0;
		while (num)
		{
			string[--count] = (num%10) + '0';
			num /= 10;				
		}
	}
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

extern "C" BOOL WINAPI _DllMainCRTStartup( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		HMODULE executable = GetModuleHandle(NULL);

		TCHAR filename[MAX_PATH];
		GetModuleFileName(executable,filename,MAX_PATH);
		//MessageBox(0,filename,TEXT("Attach Debugger"),MB_OK);

		//AllocConsole();
		if (AttachConsole(ATTACH_PARENT_PROCESS)) {
			MessageBox(0,filename,TEXT("Attach Debugger?"),MB_OK);
		}
		hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		hError = GetStdHandle(STD_ERROR_HANDLE);

		// Write byte order marks...
		if (hOutput && GetFileType(hOutput) == FILE_TYPE_DISK) {
			LONG high = 0;
			if (SetFilePointer(hOutput,0,&high,FILE_CURRENT) == 0 && high == 0)
				Write("\xEF\xBB\xBF",hOutput);
		}
		if (hError && GetFileType(hError) == FILE_TYPE_DISK) {
			LONG high = 0;
			if (SetFilePointer(hError,0,&high,FILE_CURRENT) == 0 && high == 0)
				Write("\xEF\xBB\xBF",hError);
		}

		Write("Executable filename: ");
		WriteLine(filename);
		Write("Executable address: 0x");
		WriteLine((DWORD_PTR)executable);

		WriteLine("Unsetting LAA Bit");
		if (Change4GBValue(LPVOID(executable),false) < 0) {
			WriteLine("Unsetting LAA bit failed");

			if (LPVOID(executable) != LPVOID(0x4000000)) {
				WriteLine("Attempting at default addresss 0x400000");

				if (Change4GBValue(LPVOID(0x4000000),false) < 0) {
					WriteLine("Second attempt at unsetting LAA bit failed");
				}
			} 
		}

		Write("Getting Handle to KERNEL32");
		HMODULE Kernel32 = GetModuleHandle(TEXT("KERNEL32"));
		if (Kernel32 == NULL) {
			DWORD error = GetLastError();
			Write(" - Failed -> ");
			WriteError(error);
		}
		else {
			WriteLine(" - Succeeded");
		}

		WriteLine("Redirecting CreateFileA");
		REDIRECT_FUNCTION(Kernel32,CreateFileA);

#if 0
#ifndef USE_THREADED_GETTICKCOUNT
		WriteLine("Redirecting GetTickCount");
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
		Write("Attempting to load SKSE");
		HMODULE skse = LoadLibrary(TEXT("skse_steam_loader.dll"));
		if (skse == NULL) {
			DWORD error = GetLastError();
			Write(" - Failed -> ");
			WriteError(error);
		}
		else {
			WriteLine(" - Succeeded");
		}
	}
    return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

