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
#include "injection.h"
#include <stddef.h>


__declspec(naked) DWORD_PTR WINAPI Injection::GetInjectionCode(LPVOID &start)
{

	// Ok this gets a little complicated
	__asm {
		jmp INJECTED_END
INJECTED_START:
#ifdef _DEBUG
		//INT 3
#endif
		// HMODULE helper = injection->LoadLibrary(injection->szDllName);
		MOV ecx, [esp+4]
		MOV eax, [ecx].LoadLibrary
		PUSH [ecx].szDllName
		CALL eax
		
		// if (!helper) return injection->GetLastError();
		CMP eax, 0
		JNZ get_ci
		MOV ecx, [esp+4]
		call [ecx].GetLastError
		JMP end
		
	get_ci:
		// INT (WINAPI * ci)(Injection *) = injection->GetProcAddress(helper,injection->szFuncName);
		MOV ecx, [esp+4]	// Pointer to Injection structure
		PUSH [ecx].szFuncName
		PUSH eax
		MOV eax, [ecx].GetProcAddress
		CALL eax

		// if (!ci) return injection->GetLastError();
		CMP eax, 0
		JNZ call_ci
		MOV ecx, [esp+4]	// Pointer to Injection structure
		call [ecx].GetLastError
		JMP end

	call_ci:
		// return ci(injection);
		PUSH [esp+4]		// Pointer to Injection structure
		CALL eax

	end:
		ret 4

INJECTED_END:
		mov eax, [esp+4]
		mov edx, offset INJECTED_START
		mov [eax], edx
		mov eax, offset INJECTED_END
		sub eax, edx
		ret 4
	}
}

__declspec(naked) DWORD_PTR WINAPI Injection::GetStubCode(LPVOID &start)
{
	__asm {
		jmp STUB_END
STUB_START:
		xor eax, eax
		ret 4
STUB_END:
		mov eax, [esp+4]
		mov edx, offset STUB_START
		mov [eax], edx
		mov eax, offset STUB_END
		sub eax, edx
		ret 4
	}
}

