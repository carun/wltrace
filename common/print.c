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
#include <psapi.h>
#include "ptrace.h"
#include "parse.h"
#include "structs.h"
#include "write.h"

void
print_line(struct trace_block *blk, int direction, char *dll, char *fn, HANDLE thread, LPCONTEXT ctx)
{
	struct dll_spec *d = find_dll(dll);
	static DWORD stack_chunk[64], len;
	char *dll_name, *spcs = "                "; // 16 spcs
	struct fn_spec *f;
	struct child_thread *threadptr;
	static int last_op = -1, indent = 0;

	if (!blk->LongLibName)
	{
		dll_name = strrchr(dll, '\\');
		if (dll_name)
			dll_name++;
		else
			dll_name = dll;
	}
	else
		dll_name = dll;

	if ((last_op == 0) && (direction == 0))
	{
		write_out(blk->tracefile, "\n");
		indent++;
	}
	else if ((last_op == 1) && (direction == 1) && (indent > 0))
	{
		indent--;
	}

	{
		int offset = (indent > 15) ? 15 : indent;
		spcs += 16 - indent;
	}

	if (d)
	{
		f = find_fn(d, fn);
	}
	else
	{
		f = NULL;
	}

	for(threadptr = blk->thread_list; threadptr != NULL; threadptr = threadptr->next)
	{
		if (threadptr->thread_handle == thread)
		{
			break;
		}
	}

	if (direction == 0)
	{
		/* entering a library call */

		if (threadptr)
		{
			write_out(blk->tracefile, "%u: ", threadptr->thread_id);
		}

		if (f)
		{
			struct param *p;
			int c = 1;

			if (!ReadProcessMemory(blk->hProcess, (LPCVOID)ctx->Esp, stack_chunk, sizeof(DWORD) * (f->n_args + 1), &len))
			{
				WinPerror("ReadProcessMemory(fn_args)");
				if (blk->ShowRetEip)
					write_out(blk->tracefile, "%s[???] %s:%s(???)", spcs, dll_name, fn);
				else
					write_out(blk->tracefile, "%s%s:%s(???)", spcs, dll_name, fn);

				last_op = direction;
				return;
			}

			/* stack_chunk[0] contains the return address.
			 * stack_chunk[1] == arg0
			 * stack_chunk[2] == arg1
			 *   ...
			 */

			if (blk->ShowRetEip)
				write_out(blk->tracefile, "%s[%08x] %s:%s(", spcs, stack_chunk[0], dll_name, fn);
			else
				write_out(blk->tracefile, "%s%s:%s(", spcs, dll_name, fn);

			for(p = f->params; p; p=p->next, c++)
			{
				write_out(blk->tracefile, "%s%s",
						(*p->type->content_handler)(&stack_chunk[c], p, blk->hProcess, 0),
						(p->next ? "," : ""));
			}

			write_out(blk->tracefile, ")");
			last_op = direction;
			return;
		}

		if (blk->ShowRetEip)
		{
			if (!ReadProcessMemory(blk->hProcess, (LPCVOID)ctx->Esp, stack_chunk, sizeof(DWORD), &len))
			{
				WinPerror("ReadProcessMemory(fn_args)");
				stack_chunk[0] = (DWORD)~0L;
			}
			write_out(blk->tracefile, "%s[%08x] %s:%s", spcs, stack_chunk[0], dll_name, fn);
		}
		else
			write_out(blk->tracefile, "%s%s:%s", spcs, dll_name, fn);
	}
	else /* (direction == 1) */ 
	{
		/* returning from a library call */

		if (f)
		{
			if ((last_op != 0) || (f->n_out_args > 0))
			{
				if (threadptr)
				{
					write_out(blk->tracefile, "%s%u: ", (last_op == 0) ? "\n" : "", threadptr->thread_id);
				}
				else if (last_op == 0)
				{
					write_out(blk->tracefile, "\n");
				}

				write_out(blk->tracefile, "%sRETURN %s:%s%s", 
						  spcs, dll_name, f->name,
						  (f->n_out_args > 0) ? "(" : "");

				if (f->n_out_args > 0)
				{
					struct param *p;
					int c = 1;

					for(p = f->params; p; p=p->next, c++)
					{
						write_out(blk->tracefile, "%s%s",
								  (*p->type->content_handler)(&stack_chunk[c], p, blk->hProcess, 1),
								  (p->next ? "," : ""));
					}

					write_out(blk->tracefile, ")");
				}
			}
		}
		else if (last_op != 0)
		{
			if (threadptr)
			{
				write_out(blk->tracefile, "%u: ", threadptr->thread_id);
			}

			write_out(blk->tracefile, "%sRETURN %s:%s", 
					  spcs, dll_name, fn);
		}

		write_out(blk->tracefile, " = %08x\n", ctx->Eax);
	}

	last_op = direction;
}

/* $Id: print.c,v 1.5 2002/11/25 03:05:21 john Exp $ -- EOF */
