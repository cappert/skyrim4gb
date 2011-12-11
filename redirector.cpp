/*
SKyrim 4GB Function Redirector
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
#include "redirector.h"


bool RedirectFunction(LPBYTE old_func, LPBYTE new_func, LPBYTE ret_func, TempArray<const WORD> check)
{
	static const WORD a_standard[] = { STANDARD_PROLOG };
	static const WORD a_hotpatch[] = { HOTPATCH_PROLOG };
	static const WORD a_alternative[] = { ALTERNATIVE_PROLOG };
	static const WORD a_importstub[] = { IMPORTSTUB_PROLOG  };
	static const WORD a_dontcare[] = { DONTCARE_PROLOG };

	static const TempArray<const WORD> dontcare = a_dontcare;

	static const TempArray<const WORD> prologs[] = {
		a_standard,
		a_hotpatch,
		a_alternative,
		a_importstub,
	};

	bool do_hotpatch = false;

	bool failed = false;
	if (!old_func) {
		Console->WriteLine("old_func is unset");
		failed = true;
	}
	if (!new_func) {
		Console->WriteLine("old_func is unset");
		failed = true;
	}

	if (failed) return false;

	// This will contain the instructions we need
	BYTE *jmp_start;
	size_t jmp_size;
	DWORD flOldProtect;
	DWORD_PTR bytes = 0;

	__asm {
		jmp end
start: 
		jmp RedirectFunction
end: 
		mov jmp_start, offset start
		mov jmp_size, offset end
		sub jmp_size, offset start
	}

	// while the old_func is a short jump, resolve it - should perhaps support indirect jmp (FF 25 disp32)
	while (1) {
		if (*old_func == 0xEB) {
			old_func = old_func+2+(signed char)old_func[1];
		}
		//else if (old_func[0] == 0xFF || old_func[1] == 0x25) {
		//	old_func = *(LPBYTE*)old_func+2;
		//}
		else 
			break;		
	}


	// Hot patch function? 
	bool do_hot_patch = false;
	if (old_func[0] == 0x8B && old_func[1] == 0xFF) {
		int i;
		// Make sure the code before it is nop'd
		for (i = -1; i >= -5; i--) {
			if (old_func[i] != 0x90) break;
		}

		// use hot patching to do this
		if (i == -6) {
			old_func-=5;
			do_hot_patch = true;
			bytes = 7;
		}
	}

	if (!do_hot_patch) {
		// Check to see if the prolog is standard. 
		for(int j = 0; bytes == 0 && j < sizeof(prologs)/sizeof(prologs[0]); j++) {
			const TempArray<const WORD> &p = prologs[j];

			if (jmp_size<=p.size) {
				for (bytes = 0; bytes < p.size; ++bytes) {
					WORD mask = (~(p[bytes]>>8))&0xFF;
					WORD c = p[bytes]&mask;
					if ( (((LPBYTE)old_func)[bytes]&mask) != c) {
						bytes = 0;
						break;
					}
				}
			}
		}

		// if don't have ret_func, then we will set check to dontcare
		if (!ret_func) check = dontcare;

		// Prolog wasn't a standard one so check size and against passed check array
		if (bytes == 0) {

			if (check.size < jmp_size) {
				Console->Write("Failed to redirect function at ");
				Console->Write((DWORD_PTR)old_func);
				Console->Write(" to function at ");
				Console->Write((DWORD_PTR)new_func);
				Console->Write(" because the number of bytes available (");
				Console->Write((int)check.size);
				Console->Write(") was smaller than the size required (");
				Console->Write((int)jmp_size);
				Console->Write(") for the jump instruction\n");
				Console->WriteLine();
				return false;
			}

			bool isdontcare = true;
			for (bytes = 0; bytes < check.size; ++bytes) {
				WORD mask = (~(check[bytes]>>8))&0xFF;
				WORD c = check[bytes]&mask;
				if (mask != 0xFF) isdontcare = false;
				if ( (((LPBYTE)old_func)[bytes]&mask) != c) {
					Console->Write("Failed to redirect function at ");
					Console->Write((DWORD_PTR)old_func);
					Console->Write(" to function at ");
					Console->Write((DWORD_PTR)new_func);
					Console->Write(" because the prolog check failed at byte ");
					Console->Write(bytes);
					Console->Write(" - 0x");
					Console->Write((DWORD_PTR)((LPBYTE)old_func)[bytes]&mask);
					Console->Write(" (0x");
					Console->Write((DWORD_PTR)((LPBYTE)old_func)[bytes]);
					Console->Write(" & 0x");
					Console->Write((DWORD_PTR)mask);
					Console->Write(") != 0x");
					Console->Write((DWORD_PTR)c);
					Console->WriteLine();
					return false;
				}
			}	

			// The check is a don't care, so its not safe to set the return function
			if (isdontcare) ret_func = 0;
		}
	}

	if (ret_func)
	{
		// Is a function to jump to another function so go there...
		while (((unsigned char) ret_func[0]) == 0xE9)
			ret_func = ret_func+5 + *(int*)&ret_func[1]; 
		VirtualProtect(ret_func, bytes+jmp_size, PAGE_EXECUTE_READWRITE, &flOldProtect);
		if (!do_hot_patch) {
			my_memcpy(ret_func,old_func,bytes); 

			if (((unsigned char) ret_func[0]) == 0xE8 || ((unsigned char) ret_func[0]) == 0xE9) // This is a 'call' or 'jmp' instruction, needs fixup
				*(DWORD_PTR*)&ret_func[1] += old_func - ret_func; 
	
			ret_func += bytes;
		}
		my_memcpy(ret_func,jmp_start,jmp_size); 
		ret_func += jmp_size;

		*(size_t*)(ret_func-sizeof(size_t)) = old_func+bytes - ret_func;

	}

	VirtualProtect(old_func, bytes, PAGE_EXECUTE_READWRITE, &flOldProtect);
	if (!do_hot_patch) my_memset(old_func,0x90,bytes);
	my_memcpy(old_func,jmp_start,jmp_size); old_func += jmp_size;
	*(size_t*)(old_func-sizeof(size_t)) = new_func - old_func;		
	if (do_hot_patch) *(WORD*)old_func = (-7 << 8) | 0xEB; // short jmp -7

	return true;
}