#pragma once

// push    ebp
// mov     ebp, esp
// push    reg32
// push    reg32
#define STANDARD_PROLOG 0x55,0x89,0xE5,0x0F50,0x0F50

// push    ebp
// mov     ebp, esp
// sub     esp, imm8
#define ALTERNATIVE_PROLOG 0x55,0x8B,0xEC,0x83,0xEC,0xFF00

// jmp     ds:some_address
#define IMPORTSTUB_PROLOG 0xFF, 0x3805, 0xFF00, 0xFF00, 0xFF00, 0xFF00

// mov     edi, edi
// push    ebp
// mov     ebp, esp
#define HOTPATCH_PROLOG 0x8B, 0xFF, 0x55, 0x8B, 0xEC

// Kill this first 5 bytes regardless of what they are.
// If using this, ret_func will NOT be changed!
#define DONTCARE_PROLOG 0xFF00, 0xFF00, 0xFF00, 0xFF00, 0xFF00

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

template<typename T> struct TempArray {
	T *buffer;
	int size;

	TempArray() : buffer(0), size(0) {
	}

	template<int i>	TempArray(T ( & a )[i] ) : buffer(a), size(i) {
	}

	template<int i> struct TempArrayBuffer {
		T	buffer[i];
		const int size;
		
		TempArrayBuffer(T* args) : size(i) {			
			for (T *b = buffer, *end = args+i; args != end; ++args, ++b) {
				*b = *args;
			}
		}

		operator TempArray () {
			return TempArray(buffer);
		}
	};

	T& operator [] (int i) const { return buffer[i]; }

	template<int i>	static TempArray<T> Construct(T ( & a )[i] ) {
		TempArray ta = {a,i};
		return ta;
	}

	static TempArray<T> Construct() {
		return TempArray();
	}
	static TempArrayBuffer<1> Construct(T a1) {
		return TempArrayBuffer<1>(&a1);
	}
	static TempArrayBuffer<2> Construct(T a1, T) {
		return TempArrayBuffer<2>(&a1);
	}
	static TempArrayBuffer<3> Construct(T a1, T, T) {
		return TempArrayBuffer<3>(&a1);
	}
	static TempArrayBuffer<4> Construct(T a1, T, T, T) {
		return TempArrayBuffer<4>(&a1);
	}
	static TempArrayBuffer<5> Construct(T a1, T, T, T, T) {
		return TempArrayBuffer<5>(&a1);
	}
	static TempArrayBuffer<6> Construct(T a1, T, T, T, T, T) {
		return TempArrayBuffer<6>(&a1);
	}
	static TempArrayBuffer<7> Construct(T a1, T, T, T, T, T, T) {
		return TempArrayBuffer<7>(&a1);
	}
	static TempArrayBuffer<8> Construct(T a1, T, T, T, T, T, T, T) {
		return TempArrayBuffer<8>(&a1);
	}
	static TempArrayBuffer<9> Construct(T a1, T, T, T, T, T, T, T, T) {
		return TempArrayBuffer<9>(&a1);
	}
};

#define VA_ARG_WORKAROUND(p,...) p,__VA_ARGS__

#define REDIRECT_FUNCTION(module,name,...) \
	RedirectFunction((LPBYTE) GetProcAddress(module,#name), (LPBYTE )&name##_new, VA_ARG_WORKAROUND((LPBYTE )&name##_o, TempArray<const WORD>::Construct(__VA_ARGS__)))

extern bool RedirectFunction(LPBYTE old_func, LPBYTE new_func, LPBYTE ret_func, TempArray<const WORD> check);

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
