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


#pragma once

extern int my_stricmp(const char *left, const char *right);
extern int my_stricmp(const wchar_t *left, const wchar_t *right);

template<typename T> inline size_t my_strlen(const T *str) {
	const T *start= str;
	while (*str) ++str;
	return str-start;
}

extern void my_strcpy_s(wchar_t *dest, size_t dest_size, const wchar_t *source);
extern void my_strcpy_s(char *dest, size_t dest_size, const char *source);

template<typename T, size_t i>
inline void my_strcpy_s(T ( & dest )[i],const T *source) {
	my_strcpy_s(dest,i,source);
}

template<typename T>
inline void my_strcat_s(T* dest, size_t dest_size, const T *source) {
	size_t cur = my_strlen(dest);
	if (cur < dest_size) my_strcpy_s(dest+cur,dest_size-cur,source);
}

template<typename T, size_t i>
inline void my_strcat_s(T ( & dest )[i],const T *source) {
	size_t cur = my_strlen(dest);
	if (cur < i) my_strcpy_s(dest+cur,i-cur,source);
}

template<typename T,typename PT> 
PT my_strchr(PT str, T c)
{
	PT last = 0;

	while(*str)
	{
		if (*str == c) last = str;
		str++;
	}

	return last;
}

template<typename T,typename PT>
PT my_strrchr(PT str, T c)
{
	while(*str)
	{
		if (*str == c) return str;
		str++;
	}

	return 0;
}

extern void DwordToString(DWORD num, char string[16]);

extern int CheckFiles(HANDLE hFile1, HANDLE hFile2);
extern int CheckFilenames(LPTSTR filename1, LPTSTR filename2);

