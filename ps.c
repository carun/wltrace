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

/* Process.c
 * Mini win32 'ps' command.
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include "icommon.h"
#include "ptrace.h"
#include "write.h"

extern int debug;

static void
DoModules(HANDLE proc)
{
	DWORD needed;
	HMODULE *hlist;
	MODULEINFO modinfo;
	char basename[MAX_PATH];
	unsigned int i;

	hlist = (HMODULE*)malloc(ENUMPROC_SZ);
	if (!hlist) {
		perror("malloc()");
		return;
	}

	if (!EnumProcessModules(proc,hlist,ENUMPROC_SZ,&needed))
	{
		WinPerror("EnumProcessModules()");
		return;
	}
	else if (needed > ENUMPROC_SZ) 
	{
		error("HELP! Array required by EnumProcessModules > ENUMPROC_SZ (%u)\n",
				ENUMPROC_SZ);
		abort();
	}

	for(i=0;i<needed/sizeof(HMODULE);i++)
	{
		if (GetModuleInformation(proc,hlist[i],&modinfo,sizeof(modinfo)))
		{
			GetModuleBaseName(proc,hlist[i],basename,sizeof(basename));

			printf("\t%s\t0x%08x\t%u bytes\tentry:0x%08x\n",
					basename,		
					modinfo.lpBaseOfDll, modinfo.SizeOfImage, modinfo.EntryPoint);
		}

		if (!debug)
			break;
	}

	free(hlist);
}

static void
DoProcess(DWORD pid)
{
	HANDLE proc;

	proc = OpenProcess(PROCESS_QUERY_INFORMATION |
						PROCESS_VM_OPERATION |
						PROCESS_VM_READ |
						PROCESS_VM_WRITE |
						SYNCHRONIZE,
						FALSE,
						pid);

	if (proc == NULL) 
	{
		printf("%u\t??? (OpenProcess() failed -- %u)\n",pid, GetLastError());
		return;
	}

	if (debug)
	{
		printf("%u:\n",pid);
		DoModules(proc);
		printf("\n");
	}
	else
	{
		printf("%u ", pid);
		DoModules(proc);
	}


	CloseHandle(proc);
}

void
DoProcesses()
{
	DWORD plist[6400], clen;
	int n_processes, i;

	EnumProcesses(plist,sizeof(plist),&clen);
	n_processes = clen / sizeof(DWORD);

	for(i=0;i<n_processes;i++)
		DoProcess(plist[i]);
}

