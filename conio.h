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

#pragma once

extern HANDLE hOutput;
extern HANDLE hError;

extern void WriteLine(HANDLE h=hOutput);

extern void Write(const char *str,HANDLE h=hOutput);
extern void WriteLine(const char *str, HANDLE h=hOutput);

extern void Write(const wchar_t *str,HANDLE h=hOutput);
extern void WriteLine(const wchar_t *str, HANDLE h=hOutput);

extern void Write(DWORD_PTR val,HANDLE h=hOutput);
extern void WriteLine(DWORD_PTR val,HANDLE h=hOutput);

extern void Write(int val,HANDLE h=hOutput);
extern void WriteLine(int val,HANDLE h=hOutput);

extern void WriteError(DWORD error=GetLastError(), HANDLE h=hOutput);
