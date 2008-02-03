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

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <psapi.h>
#include "parse.h"
#include "structs.h"

#define NEW(a) (a*)calloc(1,sizeof(a))

static BOOL 
DoLib(struct exe_hook *eptr, char *libname, void **ptr)
{
	struct lib_hook *lptr;

	if (!eptr)
	{
		return TRUE;
	}

	for(lptr = eptr->libs; lptr; lptr=lptr->next)
	{
		if (!strficmp(lptr->name, libname))
		{
			*ptr = lptr;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL 
DoExeLib(struct trace_block *blk, char *basename, char *libname, void **ptr)
{
	struct exe_hook *eptr;

	if (blk->hook_patterns == NULL && blk->default_pattern == NULL)
	{
		*ptr = NULL;
		return TRUE;
	}

	for(eptr = blk->hook_patterns; eptr; eptr = eptr->next)
	{
		if (!strficmp(eptr->exe, basename))
		{
			if (DoLib(eptr, libname, ptr))
			{
				return TRUE;
			}
			else
			{
				break;
			}
		}
	}

	if (blk->default_pattern == NULL)
	{
		/* blk->hook_patterns != NULL */
		return FALSE;
	}

	if (DoLib(blk->default_pattern, libname, ptr))
	{
		return TRUE;
	}

	return FALSE;
}

BOOL 
DoFn(char *fn, void *ptr)
{
	struct lib_hook *lptr = (struct lib_hook*)ptr;
	struct fn_hook *fptr;

	if (!lptr)
	{
		return TRUE;
	}

	if (lptr->all_functions || (lptr->functions == NULL))
	{
		return TRUE;
	}

	for(fptr = lptr->functions; fptr; fptr = fptr->next)
	{
		if (fptr->is_ordinal && (fptr->ordinal == (int)fn))
		{
			return TRUE;
		}
		else if (!strcmp(fn, fptr->function))
		{
			return TRUE;
		}
	}

	return FALSE;
}

/* Exported functions */

int 
SetHookPattern(void *tracer, char *exe, char *library, char *fn)
{
	struct exe_hook *eptr;
	struct lib_hook *lptr;
	struct fn_hook *fptr;
	struct trace_block *blk;

	blk = (struct trace_block*)tracer;

	if (!exe)
	{
		eptr = blk->default_pattern;
	}
	else
	{
		for(eptr = blk->hook_patterns; eptr; eptr=eptr->next)
		{
			if (!strficmp(eptr->exe, exe))
				break;
		}
	}

	if (!eptr)
	{
		eptr = NEW(struct exe_hook);

		if (!eptr)
		{
			perror("malloc");
			exit(1);
		}

		eptr->exe = exe ? strdup(exe) : NULL;

		if (exe)
		{
			eptr->next = blk->hook_patterns;
			blk->hook_patterns = eptr;
		}
		else
		{
			blk->default_pattern = eptr;
		}
	}

	for(lptr = eptr->libs; lptr; lptr=lptr->next)
	{
		if (!strficmp(lptr->name, library))
			break;
	}

	if (!lptr)
	{
		lptr = NEW(struct lib_hook);

		lptr->name = strdup(library);
		lptr->next = eptr->libs;
		eptr->libs = lptr;
	}

	if (lptr->all_functions)
	{
		/* Hooking all functions in this library already */
		return 0;
	}

	if (!fn)
	{
		/* All functions in library */
		lptr->all_functions = TRUE;
		return 0;
	}

	for(fptr = lptr->functions; fptr; fptr=fptr->next)
	{
		if (isdigit(*fn))
		{
			if (fptr->is_ordinal && (fptr->ordinal == atoi(fn)))
			{
				break;
			}
		}
		else if ((!fptr->is_ordinal) && !strcmp(fptr->function, fn))
		{
			break;
		}
	}

	if (!fptr)
	{
		fptr = NEW(struct fn_hook);

		if (!fptr)
		{
			perror("malloc");
			exit(1);
		}

		if (isdigit(*fn))
		{
			fptr->is_ordinal = TRUE;
			fptr->ordinal = atoi(fn);
		}
		else
		{
			fptr->is_ordinal = FALSE;
			fptr->function = strdup(fn);
		}

		fptr->next = lptr->functions;
		lptr->functions = fptr;
	}

	return 0;
}

/* $Id: hookpattern.c,v 1.2 2002/11/22 07:40:02 john Exp $ -- EOF */
