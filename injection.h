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

#pragma once


struct __declspec(align(4)) Injection {
	HMODULE (WINAPI *LoadLibrary) (__in  LPCTSTR lpFileName);
	FARPROC (WINAPI *GetProcAddress) (__in  HMODULE hModule, __in  LPCSTR lpProcName);
	DWORD (WINAPI * GetLastError)(void);

	LPVOID	ADDR_buffer;

	LPTSTR	szDllName;
	LPSTR	szFuncName;

	LPTSTR	szOriginalName;

	// Buffer of strings, double null terminated
	LPTSTR  szExtraDLLs;

	static DWORD_PTR WINAPI GetInjectionCode(LPVOID &start);
	static DWORD_PTR WINAPI GetStubCode(LPVOID &start);
};
