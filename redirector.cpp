#include "stdafx.h"
#include "redirector.h"

void RedirectFunction(LPBYTE old_func, LPBYTE new_func, LPBYTE ret_func, DWORD_PTR bytes)
{
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

	if (bytes < jmp_size)
	{
		//printf ("Failed to redirect function at %p to function at %p because the number of bytes available (%i) was smaller than the size required (%i) for the jump instruction\n", old_func, new_func, bytes, jmp_size);
		return;
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
}