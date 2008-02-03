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

/* Potential bugs:
 * - all the places where ReadProcessMemory() tries to read a string of
 *	 MAX_PATH characters: if string lies at end of readable memory segment,
 *	 ReadProcessMemory() will fail if string < MAX_PATH len characters.
 * - If libraries longjmp() or use dynamic exception handling, the return 
 *	 value catching will get screwed up.
 * - If > 40960 library calls, the brkpnt_blk overflows.
 */

#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "icommon.h"
#include "parse.h"
#include "ptrace.h"
#include "ps.h"
#include "hookpattern.h"
#include "print.h"
#include "write.h"

int debug = 0;

/* For a list of privileges, see winnt.h
 * Privilege names symbolic defines begin with prefix 'SE_' 
 */

BOOL 
SetPrivilege(HANDLE hToken,LPCTSTR lpszPrivilege,BOOL bEnablePrivilege) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) 
	{
		WinPerror("LookupPrivilegeValue error"); 
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), 
						  (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL); 
 
	if (GetLastError() != ERROR_SUCCESS) 
	{ 
		WinPerror("AdjustTokenPrivileges failed");
		return FALSE; 
	} 

	return TRUE;
}

void
do_traceables(void *tracer, char *arg)
{
	char *s, *d;

	d = arg;
	while(d)
	{
		char *dll, *lib, *fn;

		s = strchr(d, ',');
		if (s) *s++ = '\0';

		dll = d;
		d = strchr(dll, ':');
		if (d == NULL)
			goto die;

		*d++ = '\0';
		if (*dll == '\0')
			dll = NULL;

		lib = d;
		d = strchr(lib, ':');
		if (d == NULL || (*d == '\0'))
			goto die;

		*d++ = '\0';
		fn = d;
		if (*fn == '\0')
			fn = NULL;

		if (SetHookPattern(tracer, dll, lib, fn)) 
		{
			error("Conflicting pattern '%s:%s:%s'\n", dll ? dll : "",
				lib, fn ? fn : "");
			exit(1);
		}

		d = s;
		continue;

die:
		error("-D must be followed by a '[import.dll]:exporting.dll:[fn_name]' argument\n");
		exit(1);
	}
}

int
main(int argc,char **argv)
{
	HANDLE ptoken;
	DWORD pid = 0;
	char *cmdline;
	int i, j, cmdlinelen = 0;
	void *tracer;
	int flags;
	FILE *tracefile;

	tracefile = stdout;

	flags = 0;

	for(i=1;i<argc;i++)
		if (*argv[i] == '-')
		{
			switch(argv[i][1]) {
			case 'a':
				DoProcesses();
				exit(0);

			case 'p':
				if (++i >= argc) 
				{
					error("-p requires an argument\n");
					exit(1);
				}
				pid = atoi(argv[i]);
				break;

			case 'd':
				flags |= FLG_DESCEND;;
				break;

			case 'D':
				if (++i >= argc) 
				{
					error("-D requires an argument\n");
					exit(1);
				}
				/* skip for now */
				break;

			case 'f':
				if (parse_config(argv[++i]))
					exit(0);
				break;

			case 'i':
				flags |= FLG_INTR_PTR;
				break;

			case 'l':
				flags |= FLG_LONG_NAME;
				break;

			case 'n':
				flags |= FLG_NTDLL;
				break;

			case 'v':
				debug = 1;
				break;

			case 'o':
				if (++i >= argc) 
				{
					error("-o requires an outout filename\n");
					exit(0);
				}

				if ((tracefile = fopen(argv[i],"w")) == NULL)
				{
					perror(argv[i]);
					exit(1);
				}
				break;
			}
		}
		else
			break;


	if ((tracer = NewTrace(tracefile, flags, 0)) == NULL)
	{
		WinPerror("NewTrace()");
		exit(1);
	}

	/* Do trace pattern arguments now that we have a trace handle. We can't create
	 * the trace handle before parsing the arguments, as we need to pass the file
	 * descriptor for the trace file to NewTrace().
	 */

	for(j=1;j<argc;j++)
		if (*argv[j] != '-')
			break;
		else if (argv[j][1] == 'D')
			do_traceables(tracer, argv[j]);

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
						  &ptoken))
	{
		WinPerror("OpenProcessToken() failed");
		exit(1);
	}

	if (!SetPrivilege(ptoken,"SeDebugPrivilege",TRUE))
	{
		WinPerror("Failed to grant myself SeDebugPrivilege");
		exit(1);
	}

	if (!pid)
	{
		for(j=i; j<argc; j++)
		{
			cmdlinelen += strlen(argv[j]) + 1;
		}

		cmdline = (char*)calloc(1,cmdlinelen + 1);

		for(j=i; j<argc; j++)
		{
			strcat(cmdline,argv[j]);
			strcat(cmdline," ");
		}

		SpawnTraceProcess(tracer, cmdline);
	}
	else
	{
		TraceProcess(tracer, pid);
	}

	return 0;
}

/* $Id: ltrace.c,v 1.9 2002/11/23 08:14:29 john Exp $ -- EOF */
