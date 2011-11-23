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

int Change4GBValue(LPVOID baseaddress, bool set)
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

	DWORD old;
	VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), PAGE_READWRITE, &old);

	if (set)
		pFileHeader->Characteristics |= IMAGE_FILE_LARGE_ADDRESS_AWARE;
	else
		pFileHeader->Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;

	DWORD oldold;
	VirtualProtect(&pFileHeader->Characteristics, sizeof(pFileHeader->Characteristics), old, &oldold);

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
	if (hOutput)
	{
		DWORD numwritten;
		WriteFile(hOutput,"CreateFile: ",12, &numwritten,0);
		WriteFile(hOutput,lpFileName,mystrlen(lpFileName), &numwritten,0);
		WriteFile(hOutput,"\n\r",2, &numwritten,0);
		FlushFileBuffers(hOutput);
	}

	int len = 0;
	CHAR new_filename[MAX_PATH+1];
	while (len < MAX_PATH && (new_filename[len] = lpFileName[len]) != 0) ++len;

	if (len == MAX_PATH) new_filename[MAX_PATH+1] = 0;

	if (len >= 12 && !mystricmp(&lpFileName[len-12],"TESV.exe.4gb")) 
	{
		my_memcpy(&new_filename[len-12],"TESV.exe",9);
		lpFileName = new_filename;		
	}

	if (hOutput)
	{
		DWORD numwritten;
		WriteFile(hOutput,"         -> ",12, &numwritten,0);
		WriteFile(hOutput,lpFileName,mystrlen(lpFileName), &numwritten,0);
		WriteFile(hOutput,"\n\r",2, &numwritten,0);
		FlushFileBuffers(hOutput);
	}


	return CreateFileA_o(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
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

	HMODULE kernel32 = GetModuleHandle(TEXT("KERNEL32"));
	REDIRECT_FUNCTION(kernel32,GetTickCount,5);

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

extern "C" BOOL WINAPI _DllMainCRTStartup( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		HMODULE executable = GetModuleHandle(NULL);

		//TCHAR filename[MAX_PATH];
		//GetModuleFileName(executable,filename,MAX_PATH);
		//MessageBox(0,filename,TEXT("Attach Debugger"),MB_OK);

		//AllocConsole();
		//hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
		//hError = GetStdHandle(STD_ERROR_HANDLE);

		Change4GBValue(LPVOID(executable),false);

		HMODULE kernel32 = GetModuleHandle(TEXT("KERNEL32"));
		
#ifndef USE_THREADED_GETTICKCOUNT
		REDIRECT_FUNCTION(kernel32,GetTickCount,5);
#else
		LARGE_INTEGER f;
		if (QueryPerformanceFrequency(&f))
		{
			DWORD tid;
			HANDLE thread = CreateThread(NULL,0,TimerThread,0,0,&tid);
		}
#endif

		REDIRECT_FUNCTION(kernel32,CreateFileA,5);
	}
    return TRUE;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif

