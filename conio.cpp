/*
SKyrim 4GB Console IO
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
#include "conio.h"

static ConIO sError = { 
	(HANDLE) 0,  &sError
};
static ConIO sOutput = { 
	(HANDLE) 0,  &sError
};
ConIO *Console = { 
	&sOutput
};

ConIO* ConIO::WriteLine() 
{
	if (h == 0) return this;

	DWORD numwritten;
	WriteFile(h,"\r\n",2, &numwritten,0);
	FlushFileBuffers(h);
	return this;
}

ConIO* ConIO::Write(const char *str) 
{
	if (h == 0) return this;

	DWORD len = 0;
	while(str[len]) ++len;

	DWORD numwritten;
	WriteFile(h,str,len,&numwritten,0);

	return this;
}

ConIO* ConIO::WriteLine(const char *str) 
{
	if (h == 0) return this;
	Write(str);
	WriteLine();
	return this;
}

ConIO* ConIO::Write(const wchar_t *str) 
{
	if (h == 0) return this;

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
	return this;
}

ConIO* ConIO::WriteLine(const wchar_t *str) 
{
	if (h == 0) return this;
	Write(str);
	WriteLine();
	return this;
}
ConIO* ConIO::Write(DWORD_PTR val) 
{
	if (h == 0) return this;

	char str[32];
	char *ptr = str+32;
	*--ptr=0;
	if (val == 0) *--ptr='0';
	else while (val) {
		int nibble = val&0xF;
		val >>= 4;

		if (nibble <= 9) *--ptr = '0' + nibble;
		else *--ptr = 'A' + nibble - 0xA;
	}

	DWORD numwritten;
	WriteFile(h,ptr,str+31-ptr,&numwritten,0);
	return this;
}
ConIO* ConIO::WriteLine(DWORD_PTR val) 
{
	if (h == 0) return this;
	Write(val);
	WriteLine();
	return this;
}
ConIO* ConIO::Write(int val)
{
	if (h == 0) return this;

	bool wasneg = val<0;
	if (wasneg) val = -val;
	char str[32];
	char *ptr = str+32;
	*--ptr=0;
	if (val == 0) *--ptr='0';
	else while (val) {
		*--ptr = '0' + val%10;
		val /= 10;
	}
	if (wasneg) *--ptr = '-';
	DWORD numwritten;
	WriteFile(h,ptr,str+31-ptr,&numwritten,0);
	return this;
}
ConIO* ConIO::WriteLine(int val)
{
	if (h == 0) return this;
	Write(val);
	WriteLine();
	return this;
}

ConIO* ConIO::WriteError(DWORD error)
{
	if (h == 0) return this;
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
	return this;
}

ConIO* ConIO::WriteError(const char *str, DWORD error)
{
	if (h == 0) return this;
	Write(str);
	WriteError(error);
	return this;
}
ConIO* ConIO::WriteError(const wchar_t *str, DWORD error)
{
	if (h == 0) return this;
	Write(str);
	WriteError(error);
	return this;
}
