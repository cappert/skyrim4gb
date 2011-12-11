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

#include "stdafx.h"
	
int my_stricmp(const char *left, const char *right)
{
	while (*left && *right)
	{
		int l = *left++;
		int r = *right++;

		if (l >= 'a' && l <= 'z') l -= 0x20;
		if (r >= 'a' && r <= 'z') r -= 0x20;

		int res = l - r;
		if (res != 0) return res;
	}

	return *left - *right;
}
int my_stricmp(const wchar_t *left, const wchar_t *right)
{
	while (*left && *right)
	{
		int l = *left++;
		int r = *right++;

		if (l >= 'a' && l <= 'z') l -= 0x20;
		if (r >= 'a' && r <= 'z') r -= 0x20;

		int res = l - r;
		if (res != 0) return res;
	}

	return *left - *right;
}

inline void my_strcpy_s(wchar_t *dest, size_t dest_size, const wchar_t *source)
{
	if (dest_size == 0) return;
	wchar_t *end = dest+dest_size;
	do {
		if (!(*dest++ = *source++)) return;
	} while(dest != end);
	dest[-1] = 0;
}

inline void my_strcpy_s(char *dest, size_t dest_size, const char *source)
{
	if (dest_size == 0) return;
	char *end = dest+dest_size;
	do {
		if (!(*dest++ = *source++)) return;
	} while(dest != end);
	dest[-1] = 0;
}

void DwordToString(DWORD num, char string[16])
{
	int count = 0;
	DWORD t = num;

	while (t)
	{
		count++;
		t /= 10;				
	}

	if (count == 0)
	{
		string[0] = '0';
		string[1] = 0;
	}
	else
	{
		string[count] = 0;
		while (num)
		{
			string[--count] = (num%10) + '0';
			num /= 10;				
		}
	}
}

int CheckFiles(HANDLE hFile1, HANDLE hFile2)
{

	BY_HANDLE_FILE_INFORMATION info1;
	BY_HANDLE_FILE_INFORMATION info2;
    BOOL r1 = GetFileInformationByHandle(hFile1, &info1);
    BOOL r2 = GetFileInformationByHandle(hFile2, &info2);

	if (!r1 && !r2) {
		return 0;
	}
	else if (r1 && !r2) {
		return 1;
	}
	else if (!r1 && r2) {
		return -1;
	}

	if (info1.dwVolumeSerialNumber != info2.dwVolumeSerialNumber) {
		return info1.dwVolumeSerialNumber - info2.dwVolumeSerialNumber;
	}

	if (info1.nFileIndexHigh != info2.nFileIndexHigh) {
		return info1.nFileIndexHigh - info2.nFileIndexHigh;
	}
	return info1.nFileIndexLow - info2.nFileIndexLow;
}

int CheckFilenames(LPTSTR filename1, LPTSTR filename2)
{
	HANDLE hFile1 = CreateFile(filename1,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_ATTRIBUTE_NORMAL,0);
	HANDLE hFile2 = CreateFile(filename2,0,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,0,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_ATTRIBUTE_NORMAL,0);

	if (!hFile1 && !hFile2) {
		return 0;
	}
	else if (hFile1 && !hFile2) {
		CloseHandle(hFile1);
		return 1;
	}
	else if (!hFile1 && hFile2) {
		CloseHandle(hFile2);
		return -1;
	}

	int res = CheckFiles(hFile1,hFile2);

	CloseHandle(hFile1);
	CloseHandle(hFile2);

	return res;
}
