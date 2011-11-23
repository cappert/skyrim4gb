/*
Fallout New Vegas 4GB Loader
Copyright (C) 2010  Renee Stanley (the.wench@wenchy.net)

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

// TODO: reference any additional headers you need in STDAFX.H
// and not in this file

#pragma function(memset)
#pragma function(memcmp)
#pragma function(memcpy)
 
void* memset(void*dst,int val, size_t size)
{	
	LPBYTE d =(LPBYTE) dst;
	while(size--) *d++ = val;
	return dst;
}

void* memcpy(void*dst,const void*src, size_t size)
{	
	LPBYTE d =(LPBYTE) dst;
	const char *s =(const char *) src;
	while(size--) *d++ = *s++;
	return dst;
}

int memcmp(const void *_Buf1, const void *_Buf2, size_t _Size)
{
	const char *b1 =(const char *) _Buf1;
	const char *b2 =(const char *) _Buf2;
	while(_Size--) {
		int diff = *b1++ - *b2++;
		if (diff != 0) return diff;
	}
	return 0;
}