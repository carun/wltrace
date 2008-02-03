/*
    LTRACE32.C -- cruddy win32 trace program.

    Copyright (C) 2002  johnbrazel@gmail.com

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef _PTRACE_H
#define _PTRACE_H

extern void *NewTrace(void*, int, unsigned long);

#define FLG_DESCEND			0x01
#define FLG_INTR_PTR		0x02
#define FLG_LONG_NAME		0x04
#define FLG_NTDLL			0x08
#define FLG_DEBUG			0x80

extern void SpawnTraceProcess(void*, char*);
extern void TraceProcess(void*, DWORD);
extern void StopTracing(void*);

extern void ReadMemory(HANDLE, LPVOID, LPVOID, DWORD);
extern BOOL ProtectedWriteProcessMemory(HANDLE, LPVOID, LPVOID, DWORD, LPDWORD);
extern void WinPerror(char*);

#endif /* _PTRACE_H */
