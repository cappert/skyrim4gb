#include "stdafx.h"
#include "redirector.h"

extern HANDLE hOutput;

extern void WriteLine(HANDLE h=hOutput);

extern void Write(const char *str,HANDLE h=hOutput);
extern void WriteLine(const char *str, HANDLE h=hOutput);
extern void Write(DWORD_PTR val,HANDLE h=hOutput);
extern void WriteLine(DWORD_PTR val,HANDLE h=hOutput);
extern void Write(int val,HANDLE h=hOutput);
extern void WriteLine(int val,HANDLE h=hOutput);


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

	bool failed = false;
	if (!old_func) {
		WriteLine("old_func is unset");
		failed = true;
	}
	if (!new_func) {
		WriteLine("old_func is unset");
		failed = true;
	}

	if (failed) return false;

	// This will contain the instructions we need
	BYTE *jmp_start;
	size_t jmp_size;
	DWORD flOldProtect;

	__asm {
		jmp end
start: 
		jmp RedirectFunction
end: 
		mov jmp_start, offset start
		mov jmp_size, offset end
		sub jmp_size, offset start
	}

	// while the old_func is a short jump, resolve it
	while (*old_func == 0xEB) {
		old_func = old_func+2+(signed char)old_func[1];
	}

	DWORD_PTR bytes = 0;

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
			Write("Failed to redirect function at ");
			Write((DWORD_PTR)old_func);
			Write(" to function at ");
			Write((DWORD_PTR)new_func);
			Write(" because the number of bytes available (");
			Write((int)check.size);
			Write(") was smaller than the size required (");
			Write((int)jmp_size);
			Write(") for the jump instruction\n");
			WriteLine();
			return false;
		}

		bool isdontcare = true;
		for (bytes = 0; bytes < check.size; ++bytes) {
			WORD mask = (~(check[bytes]>>8))&0xFF;
			WORD c = check[bytes]&mask;
			if (mask != 0xFF) isdontcare = false;
			if ( (((LPBYTE)old_func)[bytes]&mask) != c) {
				Write("Failed to redirect function at ");
				Write((DWORD_PTR)old_func);
				Write(" to function at ");
				Write((DWORD_PTR)new_func);
				Write(" because the prolog check failed at byte ");
				Write(bytes);
				Write(" - 0x");
				Write((DWORD_PTR)((LPBYTE)old_func)[bytes]&mask);
				Write(" (0x");
				Write((DWORD_PTR)((LPBYTE)old_func)[bytes]);
				Write(" & 0x");
				Write((DWORD_PTR)mask);
				Write(") != 0x");
				Write((DWORD_PTR)c);
				WriteLine();
				return false;
			}
		}	

		// The check is a don't care, so its not safe to set the return function
		if (isdontcare) ret_func = 0;
	}

	if (ret_func)
	{
		// Is a function to jump to another function so go there...
		while (((unsigned char) ret_func[0]) == 0xE9)
			ret_func = ret_func+5 + *(int*)&ret_func[1]; 
		VirtualProtect(ret_func, bytes+jmp_size, PAGE_EXECUTE_READWRITE, &flOldProtect);
		my_memcpy(ret_func,old_func,bytes); 

		if (((unsigned char) ret_func[0]) == 0xE8 || ((unsigned char) ret_func[0]) == 0xE9) // This is a 'call' or 'jmp' instruction, needs fixup
			*(DWORD_PTR*)&ret_func[1] += old_func - ret_func; 
	
		ret_func += bytes;
		my_memcpy(ret_func,jmp_start,jmp_size); 
		ret_func += jmp_size;

		*(size_t*)(ret_func-sizeof(size_t)) = old_func+bytes - ret_func;

	}

	VirtualProtect(old_func, bytes, PAGE_EXECUTE_READWRITE, &flOldProtect);
	my_memset(old_func,0x90,bytes);
	my_memcpy(old_func,jmp_start,jmp_size); old_func += jmp_size;
	*(size_t*)(old_func-sizeof(size_t)) = new_func - old_func;		

	return true;
}