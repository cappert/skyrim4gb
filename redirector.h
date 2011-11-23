#pragma once

#define LOTS_OF_NOPS(addr) __asm { \
		__asm mov eax, addr __asm mov ecx, eax \
		__asm mov edx, eax \
		__asm nop __asm nop __asm nop __asm nop  \
		__asm nop __asm nop __asm nop __asm nop  \
		__asm nop __asm nop __asm nop __asm nop  \
		__asm nop __asm nop __asm nop __asm nop  } 

#define REDIRECTABLE_FUNCTION_EX(ret,callconv, name,args) \
	__declspec(noinline) static ret callconv name##_o args { LOTS_OF_NOPS(name##_o) } \
	__declspec(noinline) static ret callconv name##_new args

#define REDIRECT_FUNCTION(module,name,prolog) \
	RedirectFunction((LPBYTE) GetProcAddress(module,#name), (LPBYTE )&name##_new, (LPBYTE )&name##_o, prolog)

extern void RedirectFunction(LPBYTE old_func, LPBYTE new_func, LPBYTE ret_func, DWORD_PTR bytes);

inline void my_memcpy(LPBYTE dest, CONST BYTE *src, int count)
{
	while (count--) *dest++ = *src++;
}
inline void my_memcpy(LPVOID dest, LPCVOID src, int count)
{
	my_memcpy((LPBYTE)dest, (CONST BYTE *) src, count);
}
inline void my_memset(LPBYTE dest, BYTE src, int count)
{
	while (count--) *dest++ = src;
}
inline void my_memset(LPVOID dest, BYTE src, int count)
{
	my_memset((LPBYTE)dest,src,count);
}

inline int mystrlen(const char *left)
{
	int count = 0;
	while (*left++) count++;
	return count;
}
inline int mystrlen(const WCHAR *left)
{
	int count = 0;
	while (*left++) count++;
	return count;
}
