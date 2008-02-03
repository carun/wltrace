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

/* Ptrace.c
 * The main process tracing code.
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <conio.h>
#include "ptrace.h"
#include "icommon.h"	// ENUM_PROC_SZ
#include "parse.h"		// strficmp()
#include "structs.h"
#include "hookpattern.h"
#include "print.h"
#include "write.h"

extern int debug;

static HANDLE
FindThreadById(struct trace_block *block, DWORD id)
{
	struct child_thread *ttmp = block->thread_list;

	while(ttmp)
	{
		if (ttmp->thread_id == id)
			return ttmp->thread_handle;
		ttmp = ttmp->next;
	}
	return NULL;
}

static char*
mkordinal(int ordinal, char *pname)
{
	sprintf(pname,"func.%i",ordinal);
	return pname;
}

static struct export_entry*
match_ex_by_symbol(struct library *lib, char *symbol)
{
	int i;

	for(i = 0; i < lib->export_table_sz; i++)
	{
		if (!strcmp(lib->export_table[i].name, symbol))
		{
			return &lib->export_table[i];
		}
	}
	return NULL;
}

static struct export_entry*
match_ex_by_ordinal(struct library *lib, DWORD ordinal)
{
	if (ordinal >= lib->export_ordinal_base && 
		(ordinal - lib->export_ordinal_base) < (DWORD)lib->export_table_sz)
	{
		return &lib->export_table[(ordinal - lib->export_ordinal_base)];
	}
	return NULL;
}

static BOOL
match_symbol(struct library *lib, char *symbol, LPVOID *new_addr, LPVOID *orig_addr)
{
	struct export_entry *e = match_ex_by_symbol(lib,symbol);

	if (e == NULL)
	{
		return FALSE;
	}
	else
	{
		*new_addr = e->new_addr;
		if (orig_addr) *orig_addr = e->orig_addr;
		return TRUE;
	}
}

static BOOL
match_ordinal(struct library *lib, DWORD symbol, LPVOID *new_addr, LPVOID *orig_addr)
{
	struct export_entry *e = match_ex_by_ordinal(lib, symbol);

	if (e == NULL)
	{
		return FALSE;
	}
	else
	{
		*new_addr = e->new_addr;
		if (orig_addr) *orig_addr = e->orig_addr;
		return TRUE;
	}
}

static void
resolve_forwarder(struct trace_block *blk, struct export_entry *eentry)
{
	struct export_entry *e;

	if (!eentry->forwarder)
		return;

	if (debug) write_out(blk->tracefile, "resolving %s.%s\n", eentry->parent->name, eentry->name);

	if (eentry->fwdr_info.is_ordinal)
	{
		e = match_ex_by_ordinal(eentry->fwdr_info.lib, eentry->fwdr_info.u.ordinal);
	}
	else
	{
		e = match_ex_by_symbol(eentry->fwdr_info.lib, eentry->fwdr_info.u.symbol);
	}

	if (e == NULL)
	{
		error("Unresolved forwarder %s.", eentry->fwdr_info.lib->name);

		if (eentry->fwdr_info.is_ordinal)
		{
			error("%u\n",eentry->fwdr_info.u.ordinal);
		}
		else
		{
			error("%s\n",eentry->fwdr_info.u.symbol);
		}

		exit(1);
	}

	if (e->forwarder)
	{
		resolve_forwarder(blk, e);
	}

	eentry->orig_addr = e->orig_addr;
}


static void
link_import_table(struct trace_block *blk, struct library *lib, struct link *dependent)
{
	DWORD len, import_lookup_table, import_lookup, iat, iat_entry;
	void *ptr;

	import_lookup_table = dependent->import_lookup_table;
	iat = dependent->iat;

	if (!DoExeLib(blk, dependent->referer->name, lib->name, &ptr))
	{
		if (debug) write_out(blk->tracefile, "Not hooking, in accordance with trace hook rules provided.\n");
		return;
	}

	while(1)
	{
		LPVOID new_addr, old_addr;
		BOOL success;

		if (!ReadProcessMemory(blk->hProcess, (LPCVOID)import_lookup_table, 
								&import_lookup, sizeof(DWORD), &len))
			break;

		if (!ReadProcessMemory(blk->hProcess, (LPCVOID)iat, &iat_entry,
								sizeof(DWORD), &len))
			break;

		if (import_lookup == 0)
			break;

		if (import_lookup & 0x80000000)
		{
			/* ordinal lookup */

			if (DoFn((char*)(import_lookup & 0x7FFFFFFF), ptr))
			{
				char pbuffer[64], *pname = mkordinal((int)(import_lookup & 0x7FFFFFFF), pbuffer);
				if (debug) write_out(blk->tracefile, "\t<%s>\t%08x\t", pname, iat_entry);
				success = match_ordinal(lib,(import_lookup & 0x7FFFFFFF),&new_addr, &old_addr);
			}
			else
			{
				success = FALSE;
			}
		}
		else
		{
			/* name lookup */
			char procname[MAX_PATH];
			char *name = ((char*)dependent->referer->libinfo.lpBaseOfDll + (import_lookup & 0x7FFFFFFF));

			if (!ReadProcessMemory(blk->hProcess, (LPCVOID)name, procname, 
									sizeof(procname), &len))
			{
				if (debug) write_out(blk->tracefile, "\t???\t%08x\t", iat_entry);
				success = FALSE;
			}
			else
			{
				if (DoFn(procname + 2, ptr))
				{
					if (debug) write_out(blk->tracefile, "\t%s\t%08x\t", procname + 2, iat_entry);
					success = match_symbol(lib,procname + 2,&new_addr,&old_addr);
				}
				else
				{
					success = FALSE;
				}
			}
		}

		if (!success)
		{
			if (debug) write_out(blk->tracefile, "-> FAILED\n");
		}
		else
		{
			if (debug) write_out(blk->tracefile, "->\t%08x\n", new_addr);

			if (!ProtectedWriteProcessMemory(blk->hProcess, (LPVOID)iat, (LPVOID)&new_addr, 
											 sizeof(DWORD), &len))
			{
				WinPerror("hook failed");
			}
		}

		(char*)import_lookup_table += sizeof(DWORD);
		(char*)iat += sizeof(DWORD);

	} /* while(1) */
}

static void
unlink_import_table(struct trace_block *blk, struct library *lib, struct link *dependent)
{
	DWORD len, import_lookup_table, import_lookup, iat, iat_entry;
	void *ptr;

	import_lookup_table = dependent->import_lookup_table;
	iat = dependent->iat;

	if (!DoExeLib(blk, dependent->referer->name, lib->name, &ptr))
	{
		/* Not hooked originally, no need to unhook. */
		return;
	}

	while(1)
	{
		LPVOID new_addr, old_addr;
		BOOL success;

		if (!ReadProcessMemory(blk->hProcess, (LPCVOID)import_lookup_table, 
								&import_lookup, sizeof(DWORD), &len))
			break;

		if (!ReadProcessMemory(blk->hProcess, (LPCVOID)iat, &iat_entry,
								sizeof(DWORD), &len))
			break;

		if (import_lookup == 0)
			break;

		success = FALSE;

		if (import_lookup & 0x80000000)
		{
			/* ordinal lookup */

			if (DoFn((char*)(import_lookup & 0x7FFFFFFF), ptr))
			{
				char pbuffer[64], *pname = mkordinal((int)(import_lookup & 0x7FFFFFFF), pbuffer);
				success = match_ordinal(lib,(import_lookup & 0x7FFFFFFF),&new_addr, &old_addr);
			}
		}
		else
		{
			/* name lookup */
			char procname[MAX_PATH];
			char *name = ((char*)dependent->referer->libinfo.lpBaseOfDll + (import_lookup & 0x7FFFFFFF));

			if (ReadProcessMemory(blk->hProcess, (LPCVOID)name, procname, sizeof(procname), &len) &&
				DoFn(procname + 2, ptr))
			{
				success = match_symbol(lib,procname + 2,&new_addr,&old_addr);
			}
		}

		if (success)
		{
			if (!ProtectedWriteProcessMemory(blk->hProcess, (LPVOID)iat, (LPVOID)&old_addr, 
											 sizeof(DWORD), &len))
			{
				WinPerror("Unhook failed");
			}
		}

		(char*)import_lookup_table += sizeof(DWORD);
		(char*)iat += sizeof(DWORD);

	} /* while(1) */
}

static struct library *
add_library(struct trace_block *blk, char *name)
{
	struct library *lptr = (struct library*)malloc(sizeof(*lptr));

	if (!lptr)
	{
		perror("malloc(struct library)");
		exit(1);
	}

	memset(lptr,0,sizeof(*lptr));
	lptr->name = strdup(name);
	lptr->next = blk->library_list;
	blk->library_list = lptr;

	return lptr;
}

static void
remove_library(struct trace_block *blk, struct library *lptr)
{
	struct library **ll;
	struct link *l, *nl;

	free(lptr->name);
	free(lptr->export_table);
	
	l = lptr->dependency_list;
	while(l)
	{
		nl = l->next;
		free(l);
		l = nl;
	}

	for(ll = &blk->library_list; (*ll)->next; ll = &(*ll)->next)
	{
		if ((*ll)->next == lptr)
		{
			(*ll)->next = lptr->next;
			free(lptr);
			break;
		}
	}
}

static struct library *
find_library(struct trace_block *blk, char *libname)
{
	struct library *ll;

	for(ll = blk->library_list; ll; ll = ll->next)
	{
		/* Both ll->name and libname can be either base filenames,
		 * or full pathnames. Ensure that we only compare the last
		 * components (ie 2 basenames) unless both ll->name and 
		 * libname are full pathnames.
		 */

		if (!strficmp(ll->name, libname))
			return ll;
	}

	return NULL;
}

static struct library *
find_library_by_base(struct trace_block *blk, LPVOID base_addr)
{
	struct library *ll;

	for(ll = blk->library_list; ll; ll = ll->next)
	{
		/* Both ll->name and libname can be either base filenames,
		 * or full pathnames. Ensure that we only compare the last
		 * components (ie 2 basenames) unless both ll->name and 
		 * libname are full pathnames.
		 */

		if (ll->libinfo.lpBaseOfDll == base_addr)
			return ll;
	}

	return NULL;
}

static void
add_referer(struct trace_block *blk, struct library *lptr, char *DLLname, 
			DWORD import_lookup_table, DWORD iat)
{
	struct library *ll;
	struct link *l = (struct link*)malloc(sizeof(*l));

	if (!l) {
		perror("malloc(struct link)");
		exit(1);
	}

	ll = find_library(blk, DLLname);

	if (!ll)
	{
		ll = add_library(blk, DLLname);	/* This will be assigned the full pathname of the DLL
										 * when said DLL is loaded (ie don't try and guess the
										 * full pathname of the library referred to by DLLname.
										 */
	}

	l->referer = lptr;
	l->import_lookup_table = import_lookup_table;
	l->iat = iat;

	l->next = ll->dependency_list;
	ll->dependency_list = l;

	if (ll->valid)
	{
		/* Link in the import address table now */
		if (debug) write_out(blk->tracefile, " Linking %s exports into %s IAT...\n", ll->name, lptr->name);
		link_import_table(blk, ll, l);
	}
	/* else it will be done when the actual library is loaded */
	else if (debug) write_out(blk->tracefile, "Making %s dependent on %s\n",l->referer->name, ll->name);
}

static void
alloc_hook_addr(struct trace_block *blk, struct export_entry *fn)
{
	if (blk->int3_deref == NULL)
	{
		blk->int3_deref = (struct export_entry**)calloc(blk->brkpnt_blksz, sizeof(struct export_entry*));
		if (blk->int3_deref == NULL)
		{
			perror("calloc(int3_deref table)");
			exit(1);
		}
	}

	if (blk->hook_count >= blk->brkpnt_blksz)
	{
		error("WARNING: int3_deref table overflow\n");
		fn->new_addr = fn->orig_addr;
		return;
	}

	blk->int3_deref[blk->hook_count] = fn;
	fn->new_addr = (LPVOID)((char*)blk->brkpnt_blk + blk->hook_count);
	blk->hook_count++;
}


static void
HookLibraries(struct trace_block *blk)
{
	struct link *l;
	struct library *lptr;
	char basename[MAX_PATH];
	MODULEINFO modinfo;
	HMODULE hlist[ENUMPROC_SZ/sizeof(HMODULE)];
	DWORD needed;
	DWORD i;

	if (!EnumProcessModules(blk->hProcess, hlist,ENUMPROC_SZ,&needed))
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

	/* Identify which library has just been loaded.
	 * Don't even think about getting the library name from
	 * the LOAD_DLL_DEBUG_EVENT struct: it's never there. 
	 */

	for(i=0; i<(needed/sizeof(HMODULE)); i++)
	{
		if (!GetModuleInformation(blk->hProcess, hlist[i],&modinfo,sizeof(modinfo))) {
			WinPerror("GetModuleInformation()");
			break;
		}

		GetModuleFileNameEx(blk->hProcess, hlist[i],basename,sizeof(basename));

		lptr = find_library(blk, basename);

		if (debug) write_out(blk->tracefile, "Looking for %s ... %s FOUND\n",basename, lptr ? "" : "NOT");

		if (!lptr)
		{
			lptr = add_library(blk, basename);
		}

		if (!lptr->valid)
		{
			HANDLE *f;
			IMAGE_DOS_HEADER dos_hdr;
			IMAGE_NT_HEADERS32 nthdrs;
			DWORD len;

			/* library not assigned yet */

			if (debug) write_out(blk->tracefile, "Loading %s...\n", basename);

			memcpy(&lptr->libinfo, &modinfo, sizeof(modinfo));

			if (stricmp(lptr->name, basename))
			{
				/* The library struct pointed to by lptr was created
				 * using a base filename. Update the library struct to
				 * use the full pathname.
				 */

				free(lptr->name);
				lptr->name = strdup(basename);
			}

			f = CreateFile(lptr->name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,
							NULL);

			if (f == INVALID_HANDLE_VALUE) 
			{
				WinPerror(lptr->name);
				continue;
			}

			if ((!ReadFile(f, (LPVOID)&dos_hdr, sizeof(IMAGE_DOS_HEADER), &len, NULL)) || (len != sizeof(IMAGE_DOS_HEADER)))
			{
				error("Truncated MSDOS header\n");
				continue;
			}

			if (SetFilePointer(f, dos_hdr.e_lfanew, NULL, FILE_BEGIN) == (DWORD)-1) 
			{
				WinPerror("SetFilePointer(e_lfanew)");
				continue;
			}

			if ((!ReadFile(f, (LPVOID)&nthdrs, sizeof(IMAGE_NT_HEADERS32), &len, NULL)) || (len != sizeof(IMAGE_NT_HEADERS32)))
			{
				error("Truncated PECOFF file\n");
				continue;
			}

			CloseHandle(f);

			if (nthdrs.Signature != 0x00004550)	/* 'PE\0\0' */
			{
				error("Bad PE signature\n");
				continue;
			}

			if (nthdrs.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) 
			{
				error("%u %x\n",nthdrs.FileHeader.Machine,nthdrs.FileHeader.Machine);
				error("Unsupported architecture\n");
				continue;
			}

			if (nthdrs.FileHeader.SizeOfOptionalHeader == 0) 
			{
				error("Not an executable image\n");
				continue;
			}

			if (nthdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				error("Bad Magic number in COFF optional header\n");
				continue;
			}

			if ((nthdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) &&
				(nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0))
			{
				PIMAGE_DATA_DIRECTORY export;
				IMAGE_EXPORT_DIRECTORY edesc;
				LPVOID etable, eat, enametab, eordinaltab;
				DWORD eat_entry;
				unsigned int j;

				if (debug) write_out(blk->tracefile, " handling export table\n");

				export = &nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				etable = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + export->VirtualAddress);

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)etable, &edesc, sizeof(edesc), &len))
				{
					WinPerror("ReadProcessMemory(lib->etable[0])");
					continue;
				}

				lptr->export_table_sz = edesc.NumberOfFunctions;
				lptr->export_ordinal_base = edesc.Base;
				lptr->export_table = (struct export_entry*)calloc(edesc.NumberOfFunctions,sizeof(struct export_entry));
				if (!lptr->export_table) 
				{
					perror("calloc(export_table)");
					exit(1);
				}

				/* Do export names */

				enametab = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfNames);
				eordinaltab = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfNameOrdinals);

				for(j = 0; j < edesc.NumberOfNames; j++)
				{
					char export_name[MAX_PATH];
					LPVOID enameptr;
					WORD ordinal;

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)enametab, &enameptr, sizeof(enameptr), &len))
					{
						WinPerror("ReadProcessMemory(ename_ptr)");
						break;
					}

					enameptr = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + (DWORD)enameptr);

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)enameptr, export_name, sizeof(export_name), &len))
					{
						WinPerror("ReadProcessMemory(export_name)");
						break;
					}

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)eordinaltab, &ordinal, sizeof(ordinal), &len))
					{
						WinPerror("ReadProcessMemory(export_ordinal)");
						break;
					}

					lptr->export_table[ordinal].name = strdup(export_name);

					(char*)eordinaltab += sizeof(WORD);
					(char*)enametab += sizeof(DWORD);
				}

				eat = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfFunctions);

				for(j = 0; j < edesc.NumberOfFunctions; j++)
				{
					if (lptr->export_table[j].name == NULL)
					{
						char pname[64];
						/* function exported by ordinal only, assign human-readable name */
						lptr->export_table[j].name = strdup(mkordinal(j + edesc.Base, pname));
					}

					lptr->export_table[j].parent = lptr;

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)eat, &eat_entry, sizeof(eat_entry),&len))
					{
						WinPerror("ReadProcessMemory(eat_entry)");
						continue;
					}
					
					/* Things here get messy: if the address now stored in eat_entry
					 * lies within the export table section (.edata) of the DLL, then
					 * it is a forwarder RVA (points to another function in some other DLL).
					 * Otherwise, it is the address of the exported function itself.
					 */
					
					if ((eat_entry < export->VirtualAddress) ||
						(eat_entry >= export->VirtualAddress + export->Size))
					{
						/* Address of function */
						lptr->export_table[j].orig_addr = (LPVOID)((DWORD)lptr->libinfo.lpBaseOfDll + eat_entry);
						alloc_hook_addr(blk, &lptr->export_table[j]);
					}
					else
					{
						/* Forwarder: the address here points to a string of the
						 * form 'blahdll.procname' or 'blahdll.#32' which redirects
						 * us to another dll. These are pretty common under winnt,
						 * and cause us no small headache to actually resolve.
						 */
						char forwarder[MAX_PATH], fwd_lib[MAX_PATH];
						LPVOID fwd_string = (LPVOID)((DWORD)lptr->libinfo.lpBaseOfDll + eat_entry);
						struct library *deref;
						char *p;
						BOOL is_ordinal;
						DWORD ordinal;

						if (!ReadProcessMemory(blk->hProcess, (LPCVOID)fwd_string, forwarder, sizeof(forwarder), &len))
						{
							WinPerror("ReadProcessMemory(forwarder_ref)");
							continue;
						}

						if (debug) write_out(blk->tracefile, " FWD: %s:%s -> %s\n", lptr->name, lptr->export_table[j].name, forwarder);

						p = strchr(forwarder,'.');
						if (!p) 
						{
							error("Bad forwarder reference to %s in %s\n",
									lptr->export_table[j].name, lptr->name);
							exit(1);
						}

						*p++ = '\0';

						if (*p == '#')
						{
							/* ordinal forwarder reference */
							is_ordinal = TRUE;
							ordinal = strtoul(p+1, NULL, 10);
						}
						else
						{
							is_ordinal = FALSE;
						}

						/* Don't worry about case of the extension, find_library() uses stricmp(). */

						sprintf(fwd_lib,"%s.dll",forwarder);
						deref = find_library(blk, fwd_lib);

						if (deref == NULL)
						{
							deref = add_library(blk, fwd_lib);
						}

						if (deref->valid)
						{
							BOOL success;

							if (is_ordinal)
							{
								/* ordinal forwarder reference */
								success = match_ordinal(deref, ordinal, &lptr->export_table[j].new_addr,
														&lptr->export_table[j].orig_addr);
							}
							else
							{
								/* string forwarder reference */
								success = match_symbol(deref, p, &lptr->export_table[j].new_addr,
														&lptr->export_table[j].orig_addr);
							}

							if (!success)
							{
								error("Unresolved forwarder reference %s.%s for symbol %s in %s\n",
										forwarder, p, lptr->export_table[j].name, lptr->name);
								exit(1);
							}
							else
								alloc_hook_addr(blk, &lptr->export_table[j]);
						}
						else
						{
							/* For forwarders referring to libraries not yet loaded, wait until
							 * the actual breakpoint is triggered during runtime to resolve their
							 * final address.
							 */

							lptr->export_table[j].forwarder = TRUE;
							lptr->export_table[j].fwdr_info.is_ordinal = is_ordinal;
							lptr->export_table[j].fwdr_info.lib = deref;
							if (is_ordinal)
								lptr->export_table[j].fwdr_info.u.ordinal = (WORD)ordinal;
							else
								lptr->export_table[j].fwdr_info.u.symbol = strdup(p);

							alloc_hook_addr(blk, &lptr->export_table[j]);
						}
					}

					(char*)eat += sizeof(DWORD);
				}
			}

			if ((nthdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) &&
				(nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) &&
			    ((i == 0) || blk->descend))
			{
				PIMAGE_DATA_DIRECTORY import;
				LPVOID itable, import_lookup_table, iat;
				char DLLname[1024];

				if (debug) write_out(blk->tracefile, " handling import table\n");

				import = &nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
				itable = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + import->VirtualAddress);

				while(1)
				{
					IMAGE_IMPORT_DESCRIPTOR idesc;

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)itable, &idesc, sizeof(idesc), &len))
					{
						WinPerror("ReadProcessMemory(lib->itable[n])");
						break;
					}

					(char*)itable += sizeof(idesc);

					if (idesc.Characteristics == 0)
						/* End of Import Directory Table */
						break;

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.Name), DLLname, 
											sizeof(DLLname), &len))
					{
						WinPerror("ReadProcesMemory(lib->itable[n].name)");
						break;
					}

					/* XXX Kludge: Owing to the nature of NT asynch. procedure calls, callbacks and exceptions, 
					 * we can't reliably trace into NTDLL.DLL.
					 */

					if (strficmp(DLLname, "NTDLL.DLL") == 0 && !blk->include_ntdll)
					{
						continue;
					}

					import_lookup_table = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.OriginalFirstThunk);
					iat = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.FirstThunk);

					add_referer(blk, lptr, DLLname, (DWORD)import_lookup_table, (DWORD)iat);
				}
			}

			/* fill in any structs in the dependecy_list */

			for(l = lptr->dependency_list; l; l = l->next)
			{
				if (debug) write_out(blk->tracefile, "Retrolinking %s to %s\n",lptr->name, l->referer->name);
				link_import_table(blk, lptr, l);
			}

			lptr->valid = TRUE;
		}
	}
}

static void
UnhookLibraries(struct trace_block *blk)
{
	struct library *lptr;

	/* replace all jump tables */
	
	for(lptr = blk->library_list; lptr != NULL; lptr = lptr->next)
	{
		if (lptr->valid)
		{
			struct link *dependent;

			for(dependent = lptr->dependency_list; dependent != NULL; dependent = dependent->next)
			{
				unlink_import_table(blk, lptr, dependent);
			}

		} /* (lpr->valid) */

	} /* for(lpr=blk->library_list;...) */
}

static void
DoLoadLibrary(struct trace_block *blk, LOAD_DLL_DEBUG_INFO *dbg)
{
	/* As with HookLibraries, except we rely on a debug struct rather than the
	 * module list, to tell us where things are in memory.
	 */

	struct link *l;
	struct library *lptr;
	char basename[MAX_PATH], *lib_name_ptr;
	DWORD lib_name_len;

	if (!ReadProcessMemory(blk->hProcess, dbg->lpImageName, &lib_name_ptr,
						   sizeof(lib_name_ptr), &lib_name_len))
	{
		WinPerror("ReadProcessMemory(LoadDll.ImageNamePtr)");
		return;
	}
	else if (!lib_name_ptr)
	{
		return;
	}

	if (!ReadProcessMemory(blk->hProcess, lib_name_ptr, basename,
						   sizeof(basename), &lib_name_len))
	{
		WinPerror("ReadProcessMemory(LoadDll.ImageName)");
		return;
	}

	if (dbg->fUnicode) 
	{
		/* XXX do proper unicode->ascii conversion */

		char *ptr = basename;
		unsigned short *wptr = (unsigned short *)basename;

		while(*wptr)
		{
			*ptr++ = (char)(*wptr++ & 0xff);
		}
		*ptr = '\0';
	}

	lptr = find_library(blk, basename);

	if (debug) write_out(blk->tracefile, "Looking for %s ... %s FOUND\n",basename, lptr ? "" : "NOT");

	if (!lptr)
	{
		lptr = add_library(blk, basename);
	}

	if (!lptr->valid)
	{
		HANDLE *f;
		IMAGE_DOS_HEADER dos_hdr;
		IMAGE_NT_HEADERS32 nthdrs;
		DWORD len;

		/* library not assigned yet */

		if (debug) write_out(blk->tracefile, "Loading %s...\n", basename);

		lptr->libinfo.lpBaseOfDll = dbg->lpBaseOfDll;
		lptr->libinfo.SizeOfImage = 0;
		lptr->libinfo.EntryPoint = (LPVOID)0xffffffff;

		if (stricmp(lptr->name, basename))
		{
			/* The library struct pointed to by lptr was created
			 * using a base filename. Update the library struct to
			 * use the full pathname.
			 */

			free(lptr->name);
			lptr->name = strdup(basename);
		}

		if (dbg->hFile) 
		{
			f = dbg->hFile;
		}
		else
		{
			f = CreateFile(lptr->name, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,
							NULL);

			if (f == INVALID_HANDLE_VALUE) 
			{
				WinPerror(lptr->name);
				return;
			}
		}

		if ((!ReadFile(f, (LPVOID)&dos_hdr, sizeof(IMAGE_DOS_HEADER), &len, NULL)) || (len != sizeof(IMAGE_DOS_HEADER)))
		{
			error("Truncated MSDOS header\n");
			return;
		}

		if (SetFilePointer(f, dos_hdr.e_lfanew, NULL, FILE_BEGIN) == (DWORD)-1) 
		{
			WinPerror("SetFilePointer(e_lfanew)");
			return;
		}

		if ((!ReadFile(f, (LPVOID)&nthdrs, sizeof(IMAGE_NT_HEADERS32), &len, NULL)) || (len != sizeof(IMAGE_NT_HEADERS32)))
		{
			error("Truncated PECOFF file\n");
			return;
		}

		if (!dbg->hFile)
		{
			CloseHandle(f);
		}

		if (nthdrs.Signature != 0x00004550)	/* 'PE\0\0' */
		{
			error("Bad PE signature\n");
			return;
		}

		if (nthdrs.FileHeader.Machine != IMAGE_FILE_MACHINE_I386) 
		{
			error("%u %x\n",nthdrs.FileHeader.Machine,nthdrs.FileHeader.Machine);
			error("Unsupported architecture\n");
			return;
		}

		if (nthdrs.FileHeader.SizeOfOptionalHeader == 0) 
		{
			error("Not an executable image\n");
			return;
		}

		if (nthdrs.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		{
			error("Bad Magic number in COFF optional header\n");
			return;
		}

		if ((nthdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) &&
			(nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0))
		{
			PIMAGE_DATA_DIRECTORY export;
			IMAGE_EXPORT_DIRECTORY edesc;
			LPVOID etable, eat, enametab, eordinaltab;
			DWORD eat_entry;
			unsigned int j;

			if (debug) write_out(blk->tracefile, " handling export table\n");

			export = &nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			etable = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + export->VirtualAddress);

			if (!ReadProcessMemory(blk->hProcess, (LPCVOID)etable, &edesc, sizeof(edesc), &len))
			{
				WinPerror("ReadProcessMemory(lib->etable[0])");
				return;
			}

			lptr->export_table_sz = edesc.NumberOfFunctions;
			lptr->export_ordinal_base = edesc.Base;
			lptr->export_table = (struct export_entry*)calloc(edesc.NumberOfFunctions,sizeof(struct export_entry));
			if (!lptr->export_table) 
			{
				perror("calloc(export_table)");
				exit(1);
			}

			/* Do export names */

			enametab = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfNames);
			eordinaltab = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfNameOrdinals);

			for(j = 0; j < edesc.NumberOfNames; j++)
			{
				char export_name[MAX_PATH];
				LPVOID enameptr;
				WORD ordinal;

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)enametab, &enameptr, sizeof(enameptr), &len))
				{
					WinPerror("ReadProcessMemory(ename_ptr)");
					break;
				}

				enameptr = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + (DWORD)enameptr);

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)enameptr, export_name, sizeof(export_name), &len))
				{
					WinPerror("ReadProcessMemory(export_name)");
					break;
				}

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)eordinaltab, &ordinal, sizeof(ordinal), &len))
				{
					WinPerror("ReadProcessMemory(export_ordinal)");
					break;
				}

				lptr->export_table[ordinal].name = strdup(export_name);

				(char*)eordinaltab += sizeof(WORD);
				(char*)enametab += sizeof(DWORD);
			}

			eat = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + edesc.AddressOfFunctions);

			for(j = 0; j < edesc.NumberOfFunctions; j++)
			{
				if (lptr->export_table[j].name == NULL)
				{
					char pname[64];
					/* function exported by ordinal only, assign human-readable name */
					lptr->export_table[j].name = strdup(mkordinal(j + edesc.Base, pname));
				}

				lptr->export_table[j].parent = lptr;

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)eat, &eat_entry, sizeof(eat_entry),&len))
				{
					WinPerror("ReadProcessMemory(eat_entry)");
					continue;
				}
					
				/* Things here get messy: if the address now stored in eat_entry
				 * lies within the export table section (.edata) of the DLL, then
				 * it is a forwarder RVA (points to another function in some other DLL).
				 * Otherwise, it is the address of the exported function itself.
				 */
					
				if ((eat_entry < export->VirtualAddress) ||
					(eat_entry >= export->VirtualAddress + export->Size))
				{
					/* Address of function */
					lptr->export_table[j].orig_addr = (LPVOID)((DWORD)lptr->libinfo.lpBaseOfDll + eat_entry);
					alloc_hook_addr(blk, &lptr->export_table[j]);
				}
				else
				{
					/* Forwarder: the address here points to a string of the
					 * form 'blahdll.procname' or 'blahdll.#32' which redirects
					 * us to another dll. These are pretty common under winnt,
					 * and cause us no small headache to actually resolve.
					 */
					char forwarder[MAX_PATH], fwd_lib[MAX_PATH];
					LPVOID fwd_string = (LPVOID)((DWORD)lptr->libinfo.lpBaseOfDll + eat_entry);
					struct library *deref;
					char *p;
					BOOL is_ordinal;
					DWORD ordinal;

					if (!ReadProcessMemory(blk->hProcess, (LPCVOID)fwd_string, forwarder, sizeof(forwarder), &len))
					{
						WinPerror("ReadProcessMemory(forwarder_ref)");
						continue;
					}

					if (debug) write_out(blk->tracefile, " FWD: %s:%s -> %s\n", lptr->name, lptr->export_table[j].name, forwarder);

					p = strchr(forwarder,'.');
					if (!p) 
					{
						error("Bad forwarder reference to %s in %s\n",
								lptr->export_table[j].name, lptr->name);
						exit(1);
					}

					*p++ = '\0';

					if (*p == '#')
					{
						/* ordinal forwarder reference */
						is_ordinal = TRUE;
						ordinal = strtoul(p+1, NULL, 10);
					}
					else
					{
						is_ordinal = FALSE;
					}

					/* Don't worry about case of the extension, find_library() uses stricmp(). */

					sprintf(fwd_lib,"%s.dll",forwarder);
					deref = find_library(blk, fwd_lib);

					if (deref == NULL)
					{
						deref = add_library(blk, fwd_lib);
					}

					if (deref->valid)
					{
						BOOL success;

						if (is_ordinal)
						{
							/* ordinal forwarder reference */
							success = match_ordinal(deref, ordinal, &lptr->export_table[j].new_addr,
													&lptr->export_table[j].orig_addr);
						}
						else
						{
							/* string forwarder reference */
							success = match_symbol(deref, p, &lptr->export_table[j].new_addr,
													&lptr->export_table[j].orig_addr);
						}

						if (!success)
						{
							error("Unresolved forwarder reference %s.%s for symbol %s in %s\n",
									forwarder, p, lptr->export_table[j].name, lptr->name);
							exit(1);
						}
						else
							alloc_hook_addr(blk, &lptr->export_table[j]);
					}
					else
					{
						/* For forwarders referring to libraries not yet loaded, wait until
						 * the actual breakpoint is triggered during runtime to resolve their
						 * final address.
						 */

						lptr->export_table[j].forwarder = TRUE;
						lptr->export_table[j].fwdr_info.is_ordinal = is_ordinal;
						lptr->export_table[j].fwdr_info.lib = deref;
						if (is_ordinal)
							lptr->export_table[j].fwdr_info.u.ordinal = (WORD)ordinal;
						else
							lptr->export_table[j].fwdr_info.u.symbol = strdup(p);

						alloc_hook_addr(blk, &lptr->export_table[j]);
					}
				}

				(char*)eat += sizeof(DWORD);
			}
		}

		if ((nthdrs.OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT) &&
			(nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) &&
			blk->descend)
		{
			PIMAGE_DATA_DIRECTORY import;
			LPVOID itable, import_lookup_table, iat;
			char DLLname[1024];

			if (debug) write_out(blk->tracefile, " handling import table\n");

			import = &nthdrs.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			itable = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + import->VirtualAddress);

			while(1)
			{
				IMAGE_IMPORT_DESCRIPTOR idesc;

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)itable, &idesc, sizeof(idesc), &len))
				{
					WinPerror("ReadProcessMemory(lib->itable[n])");
					break;
				}

				(char*)itable += sizeof(idesc);

				if (idesc.Characteristics == 0)
					/* End of Import Directory Table */
					break;

				if (!ReadProcessMemory(blk->hProcess, (LPCVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.Name), DLLname, 
										sizeof(DLLname), &len))
				{
					WinPerror("ReadProcesMemory(lib->itable[n].name)");
					break;
				}

				/* XXX Kludge: Owing to the nature of NT asynch. procedure calls, callbacks and exceptions, 
				 * we can't reliably trace into NTDLL.DLL.
				 */

				if (strficmp(DLLname, "NTDLL.DLL") == 0 && !blk->include_ntdll)
				{
					continue;
				}

				import_lookup_table = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.OriginalFirstThunk);
				iat = (LPVOID)((char*)lptr->libinfo.lpBaseOfDll + idesc.FirstThunk);

				add_referer(blk, lptr, DLLname, (DWORD)import_lookup_table, (DWORD)iat);
			}
		}

		/* fill in any structs in the dependecy_list */

		for(l = lptr->dependency_list; l; l = l->next)
		{
			if (debug) write_out(blk->tracefile, "Retrolinking %s to %s\n",lptr->name, l->referer->name);
			link_import_table(blk, lptr, l);
		}

		lptr->valid = TRUE;
	}
}

static struct call_frame*
CreateCallFrame(struct trace_block *blk, DWORD RetEip, struct export_entry *fn, DWORD thread)
{
	struct child_thread *ct;
	struct call_frame *cf;

	for(ct = blk->thread_list; ct; ct = ct->next)
		if (ct->thread_id == thread)
			break;

	if (ct == NULL)
	{
		error("HELP! Breakpoint occurred in unrecognised thread %lu!\n",
				thread);
		abort();
	}

	if ((cf = (struct call_frame*)malloc(sizeof(*cf))) == NULL)
	{
		perror("malloc(call_frame)");
		exit(1);
	}

	cf->original_ret_eip = RetEip;
	cf->caller = fn;
	cf->proc_address.flagged = FALSE;
	cf->next = ct->call_stack;
	ct->call_stack = cf;

	return cf;
}

static struct call_frame*
FindCallFrame(struct trace_block *blk, DWORD thread)
{
	struct child_thread *ct;

	for(ct = blk->thread_list; ct; ct = ct->next)
		if (ct->thread_id == thread)
			break;

	if (ct == NULL)
	{
		error("HELP! Breakpoint occurred in unrecognised thread %lu!\n",
				thread);
		abort();
	}

	if (ct->call_stack == NULL)
	{
		error("HELP! Return, but no stack frames for thread %lu!\n",
				thread);
		abort();
	}

	return ct->call_stack;
}

static DWORD
RemoveCallFrame(struct trace_block *blk, DWORD Esp, DWORD thread)
{
	struct call_frame *cf;
	struct child_thread *ct;
	DWORD RetEip;

	for(ct = blk->thread_list; ct; ct = ct->next)
		if (ct->thread_id == thread)
			break;

	if (ct == NULL)
	{
		error("HELP! Breakpoint occurred in unrecognised thread %lu!\n",
				thread);
		abort();
	}

	cf = ct->call_stack;

	if (cf == NULL)
	{
		error("HELP! Return, but no stack frames for thread %lu!\n",
				thread);
		abort();
	}

	/* Pop a single call frame of the call stack. We can only assume
	 * that library functions return in a predictable manner (ie the
	 * call stack acts as a LIFO), and that no longjmp()ing or dynamic
	 * exceptions occur (between distinct library functions), unless
	 * we assign a new breakpoint address for each call frame, which
	 * would allow us to keep track of which call frame we return into
	 * (at the cost of having to manage an arbitrarily long block of
	 * int3 breakpoints inside the target process).
	 * (We could use the value of Esp to determine which call frame
	 * the code is returning into, except that most library functions
	 * use the _stdcall convention, which means the called function
	 * pops more data than it pushes).
	 */

	RetEip = cf->original_ret_eip;
	ct->call_stack = ct->call_stack->next;
	free(cf);
	return RetEip;
}

static BOOL 
DangerousProcHook(struct call_frame *cf)
{
	/* Some calls to GetProcAddress() can not be hooked, as it causes problems
	 * elsewhere. One example is when WSAStartup() calls GetProcAddress() on each
	 * of the functions it provides, exclusively for the purpose of ensuring we 
	 * aren't hooking any winsock functions(!). Unsure whether this is some kinda
	 * anti-deadlock mechanism, or whether MS are just trying to be nasty.
	 *
	 * cf->next points to the parent function (outer scope).
	 */

	if (cf->next == NULL)
	{
		return FALSE;
	}

	if (strcmp(cf->next->caller->name, "WSAStartup") == 0 &&
		(strficmp(cf->next->caller->parent->name, "ws2_32.dll") == 0 ||
		 strficmp(cf->next->caller->parent->name, "wsock32.dll") == 0))
	{
		return TRUE;
	}

	return FALSE;
}

static void
Trace(struct trace_block *master_process)
{
	DEBUG_EVENT dbg;
	struct child_thread *ttmp;
	BOOL done, process_running;
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);
	done = process_running = FALSE;

	while((!done) && WaitForDebugEvent(&dbg, INFINITE))
	{
		struct trace_block *blk, **blk_remove;

		/* Something better than linear search required here */

		for(blk = master_process; blk != NULL; blk = blk->next)
		{
			if (blk->pid == dbg.dwProcessId)
				break;
		}

		if ((blk == NULL) && 
			(dbg.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT))
		{
			error("Got debug event for unknown process %u\n", dbg.dwProcessId);

			ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
			continue;
		}

		if (blk && (!blk->current))
		{
			printf("Event %u encountered\n", dbg.dwDebugEventCode);

			if (dbg.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) 
			{
				if (!blk->libraries_unhooked)
				{
					UnhookLibraries(blk);
					blk->libraries_unhooked = TRUE;
					/* fall through */
				}
				else if (dbg.u.Exception.ExceptionRecord.ExceptionAddress == blk->brkpnt_blk)
				{
					/* return from library call, fall through & process. */
					;
				}
				else
				{
					ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_EXCEPTION_NOT_HANDLED);
					continue;
				}
			}
			else if (dbg.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT)
			{
				ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
				continue;
			}
		}

		switch(dbg.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:

			if (blk == NULL)
			{
				/* New, child process */

				blk = (struct trace_block*)calloc(1, sizeof(struct trace_block));
				if (!blk)
				{
					WinPerror("calloc(TraceBlock)");
					continue;
				}

				blk->startblk = master_process->startblk;
				blk->tracefile = master_process->tracefile;
				blk->descend = master_process->descend;
				blk->hook_count = 1;
				blk->current = TRUE;
				blk->hProcess = dbg.u.CreateProcessInfo.hProcess;
				blk->pid = dbg.dwProcessId;
				blk->hook_count = master_process->hook_count;
				blk->hook_patterns = master_process->hook_patterns;
				blk->default_pattern = master_process->default_pattern;

				blk->next = master_process->next;
				master_process->next = blk;
			}

			for(ttmp = blk->thread_list; ttmp != NULL; ttmp = ttmp->next)
			{
				if (ttmp->thread_id == dbg.dwThreadId)
					break;
			}

			if ((ttmp == NULL) && (dbg.u.CreateProcessInfo.hThread))
			{
				ttmp = (struct child_thread*)malloc(sizeof(*ttmp));
				if (!ttmp) {
					perror("malloc");
					exit(1);
				}

				ttmp->thread_handle = dbg.u.CreateProcessInfo.hThread;
				ttmp->thread_id = dbg.dwThreadId;
				ttmp->is_master = 1;
				ttmp->call_stack = NULL;
				ttmp->next = blk->thread_list;
				blk->thread_list = ttmp;

				write_out(blk->tracefile, "Thread %i created\n",ttmp->thread_id);
			}

			break;

		case EXIT_PROCESS_DEBUG_EVENT:

			for(blk_remove = &master_process; *blk_remove != NULL; blk_remove = &(*blk_remove)->next)
			{
				if ((*blk_remove)->pid == dbg.dwProcessId)
				{
					*blk_remove = (*blk_remove)->next;

					/* XXX should free the structure here */

					if (master_process == NULL)
					{
						done = TRUE;
					}

					break;
				}
			}

			break;

		case CREATE_THREAD_DEBUG_EVENT:

			/* Sigh. Win32 doesn't give us anyway to get a thread
			 * handle from a thread ID (MSDN specifically notes this fact,
			 * and mumbles some half-assed reason about deadlocking
			 * being possible if there were a way to do this lookup(?!)).
			 * So we have to keep track of every fscking thread created
			 * by the target application (ho hum yawn)).
			 */

			for(ttmp = blk->thread_list; ttmp != NULL; ttmp = ttmp->next)
			{
				if (ttmp->thread_id == dbg.dwThreadId)
					break;
			}

			if ((ttmp == NULL) && dbg.u.CreateThread.hThread)
			{
				ttmp = (struct child_thread*)malloc(sizeof(*ttmp));
				if (!ttmp) {
					perror("malloc");
					exit(1);
				}
				ttmp->thread_handle = dbg.u.CreateThread.hThread;
				ttmp->thread_id = dbg.dwThreadId;
				ttmp->is_master = 0;
				ttmp->call_stack = NULL;
				ttmp->next = blk->thread_list;
				blk->thread_list = ttmp;

				write_out(blk->tracefile, "Thread %i created\n",ttmp->thread_id);
			}

			break;

		case EXIT_THREAD_DEBUG_EVENT:

			/* ...And of course, to keep our thread-list up to date,
			 * we need to keep track of the threads that die, too...
			 */

			{
				struct child_thread **tptmp;

				for(tptmp = &blk->thread_list; (*tptmp); tptmp = &(*tptmp)->next)
					if ((*tptmp)->thread_id == dbg.dwThreadId)
					{
						ttmp = *tptmp;
						*tptmp = (*tptmp)->next;
						free(ttmp);
						break;
					}
			}

			break;

		case LOAD_DLL_DEBUG_EVENT:

			/* We ignore these events, until the execution of userland 
			 * code actually begins (ie we only listen to these events if
			 * they are caused by a call to LoadLibrary()).
			 * Winnt generates these calls during the CreateProcess() call
			 * _after_ a DLL has been loaded into memory, but _before_ it
			 * assigns values to the process' Import Address Table (IAT).
			 * Consequently, if we hook the DLL upon receipt of this event,
			 * NT is likely to overwrite our hooks immediately after we
			 * tell it to continue.
			 */

			if (process_running)
			{
				DoLoadLibrary(blk, &dbg.u.LoadDll);
			}

			break;

		case UNLOAD_DLL_DEBUG_EVENT:

			if (process_running)
			{
				struct library *lptr = find_library_by_base(blk, dbg.u.UnloadDll.lpBaseOfDll);

				if (lptr == NULL) 
				{
					error("UNLOAD_DLL: Can't find any library at base %08x\n", 
							dbg.u.UnloadDll.lpBaseOfDll);
					break;
				}

				remove_library(blk, lptr);
			}

			break;

		case EXCEPTION_DEBUG_EVENT:

#if 0
			printf("Exception %x%s\n",dbg.u.Exception.ExceptionRecord.ExceptionCode,
				dbg.u.Exception.dwFirstChance ? "(1st time)":"");
			printf("\t%s\n",dbg.u.Exception.ExceptionRecord.ExceptionFlags ? "non-continuable" : "continuable");
#endif

			if (dbg.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
			{
				CONTEXT ctx;
				HANDLE die_thread;

#if 0
				printf("Breakpoint @ %08x in thread %u\n",
						dbg.u.Exception.ExceptionRecord.ExceptionAddress,
						dbg.dwThreadId);
#endif

				if (!process_running)
				{
					/* After creating the process and loading all requisite DLLs,
					 * Winnt returns via the DebugBreakPoint() function. The first 
					 * breakpoint/trap we detect heralds the begining of execution 
					 * at the image entry point.
					 */

					LPVOID localmem;
					DWORD len;

					if (debug) write_out(blk->tracefile, "Creating breakpoint block @ %08x\n", blk->startblk);

					blk->brkpnt_blksz = sysinfo.dwPageSize * 10;
					blk->brkpnt_blk = VirtualAllocEx(blk->hProcess, (LPVOID)blk->startblk, 
													 blk->brkpnt_blksz, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
					if (blk->brkpnt_blk == NULL)
					{
						WinPerror("VirtualAllocEx(breakpoint_block) failed");
						exit(1);
					}

					/* DebugBreak() maps to ntdll.dll:DbgBreakPoint(), which
					 * on the x86 platform is merely the INT3 opcode (0xCC).
					 */

					localmem = malloc(blk->brkpnt_blksz);

					if (!localmem) 
					{
						WinPerror("malloc(localmem)");
						exit(1);
					}
								
					memset(localmem, 0xCC, blk->brkpnt_blksz);

					if (!WriteProcessMemory(blk->hProcess, blk->brkpnt_blk,
											localmem, blk->brkpnt_blksz, &len))
					{
						WinPerror("WriteProcessMemory(breakpoint_block)");
						exit(1);
					}

					write_out(blk->tracefile, "breakpoint block created & initialised\nBegin execution\n");

					HookLibraries(blk);

					process_running = TRUE;
					break;
				}

				die_thread = FindThreadById(blk, dbg.dwThreadId);

				/* We need to fill this in even though we are only
				 * Getting the context.
				 */

				ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;

				if (!GetThreadContext(die_thread,&ctx))
				{
					WinPerror("GetThreadContext()");
					exit(1);	/* XXX stop debugging */
				}
				else /* (process_running) */
				{
					DWORD indx = (DWORD)dbg.u.Exception.ExceptionRecord.ExceptionAddress;

					/* Lookup original address, use ExceptionInformation[1]
					 * as an index.
					 */

					if (indx < (DWORD)blk->brkpnt_blk || indx >= ((DWORD)blk->brkpnt_blk + blk->brkpnt_blksz))	//XXX broken
					{	
						/* not one of our breakpoints, continue */
#if 1
						write_out(blk->tracefile, "Native breakpoint @ %08x in thread %u\n",
								dbg.u.Exception.ExceptionRecord.ExceptionAddress,
								dbg.dwThreadId);
#endif
					}
					else if (indx == (DWORD)blk->brkpnt_blk)
					{
						/* Return from function. */

						struct call_frame *cf;

						cf = FindCallFrame(blk, dbg.dwThreadId);
						print_line(blk, 1, cf->caller->parent->name, cf->caller->name, die_thread, &ctx);

						ctx.ContextFlags = CONTEXT_CONTROL;

						if (cf->proc_address.flagged && !DangerousProcHook(cf))
						{
							/* GetProcAddress(): replace return value */

							if (debug) write_out(blk->tracefile, "GETPROCADDRESS() retval replaced!\n");
							ctx.Eax = (DWORD)cf->proc_address.proc->new_addr;
							if (debug) write_out(blk->tracefile, "New address for fn %s is %08x\n", 
												cf->proc_address.proc->name, cf->proc_address.proc->new_addr);

							ctx.ContextFlags |= CONTEXT_INTEGER;
						}

						ctx.Eip = RemoveCallFrame(blk, ctx.Esp, dbg.dwThreadId);
					}
					else
					{
						indx -= (DWORD)blk->brkpnt_blk;

						if (blk->int3_deref[indx]->forwarder)
						{
							resolve_forwarder(blk, blk->int3_deref[indx]);
						}

						print_line(blk, 0, blk->int3_deref[indx]->parent->name, blk->int3_deref[indx]->name, die_thread, &ctx);

						/* Hook return address. */

						do {
							DWORD RetEip, len;
							struct call_frame *cf;

							if (!ReadProcessMemory(blk->hProcess, (LPCVOID)ctx.Esp, &RetEip, sizeof(DWORD), &len))
							{
								WinPerror("ReadProcessMemory(Return-EIP)");
								break;
							}

							/* Replace the return address with the address of a known
							 * breakpoint opcode. When this breakpoint is triggered, we
							 * examine the value of the stack pointer, to determine which
							 * call frame we have just returned into.
							 * Ergo, we know which win32 function has just returned.
							 */

							if (!WriteProcessMemory(blk->hProcess, (LPVOID)ctx.Esp, (LPVOID)&blk->brkpnt_blk, sizeof(LPVOID), &len))
							{
								WinPerror("WriteProcessMemory(Return-EIP)");
								break;
							}

							/* Flag return value if function was KERNEL32.DLL:GetProcAddress() */

							cf = CreateCallFrame(blk, RetEip, blk->int3_deref[indx], dbg.dwThreadId);

							if (strficmp(blk->int3_deref[indx]->parent->name, "KERNEL32.DLL") == 0 &&
								strficmp(blk->int3_deref[indx]->name, "GetProcAddress") == 0)
							{
								DWORD stack_chunk[3], len;
								char Basename[MAX_PATH];
								struct library *lptr;

								/* Read the 2 args */

								if (!ReadProcessMemory(blk->hProcess, (LPCVOID)ctx.Esp, stack_chunk, sizeof(DWORD) * 3, &len))
								{
									WinPerror("ReadProcessMemory(GetProcAddress.args)");
									break;
								}

								if (!GetModuleBaseName(blk->hProcess, (HMODULE)stack_chunk[1], Basename, sizeof(Basename)))
								{
									WinPerror("GetModuleBaseName(GetProcAddress.args[0])");
									break;
								}

								lptr = find_library(blk, Basename);
								if (!lptr)
								{
									error("GetProcAddr() called for unhandled library %s\n", Basename);
									break;
								}

								if (stack_chunk[2] & 0x80000000)
								{
									/* ordinal */
									cf->proc_address.proc = match_ex_by_ordinal(lptr, stack_chunk[2]);
								}
								else
								{
									/* function name */
									if (!ReadProcessMemory(blk->hProcess, (LPVOID)stack_chunk[2], Basename, sizeof(Basename), &len))
									{
										WinPerror("ReadProcessMemory(GetProcAddress.args[1])");
										break;
									}

									cf->proc_address.proc = match_ex_by_symbol(lptr, Basename);
								}

								if (!cf->proc_address.proc)
								{
									/* Assume that GetProcAddress() is being called on a non-existant function. */
									if (debug) write_out(blk->tracefile, "Couldn't find function '%s' in %s: return value will not be hooked\n",
														lptr->name, Basename);
									break;
								}

								cf->proc_address.flagged = TRUE;
							}

						} while(0);

						ctx.Eip = (DWORD)blk->int3_deref[indx]->orig_addr;
						ctx.ContextFlags = CONTEXT_CONTROL;
					}

					if (!SetThreadContext(die_thread,&ctx))
					{
						WinPerror("SetThreadContext()");
						exit(1);	/* XXX stop debugging */
					}
				}
			}
			else
			{
				switch(dbg.u.Exception.ExceptionRecord.ExceptionCode)
				{
				case EXCEPTION_ACCESS_VIOLATION:
					write_out(blk->tracefile, "EXCEPTION_ACCESS_VIOLATION\n");
					break;
				case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
					write_out(blk->tracefile, "EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
					break;
				case EXCEPTION_DATATYPE_MISALIGNMENT: 
					write_out(blk->tracefile, "EXCEPTION_DATATYPE_MISALIGNMENT\n");
					break;
				case EXCEPTION_FLT_DENORMAL_OPERAND:
					write_out(blk->tracefile, "EXCEPTION_FLT_DENORMAL_OPERAND\n");
					break;
				case EXCEPTION_FLT_DIVIDE_BY_ZERO:
					write_out(blk->tracefile, "EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
					break;
				case EXCEPTION_FLT_INEXACT_RESULT:
					write_out(blk->tracefile, "EXCEPTION_FLT_INEXACT_RESULT\n");
					break;
				case EXCEPTION_FLT_INVALID_OPERATION:
					write_out(blk->tracefile, "EXCEPTION_FLT_INVALID_OPERATION\n");
					break;
				case EXCEPTION_FLT_OVERFLOW:
					write_out(blk->tracefile, "EXCEPTION_FLT_OVERFLOW\n");
					break;
				case EXCEPTION_FLT_STACK_CHECK:
					write_out(blk->tracefile, "EXCEPTION_FLT_STACK_CHECK\n");
					break;
				case EXCEPTION_FLT_UNDERFLOW:
					write_out(blk->tracefile, "EXCEPTION_FLT_UNDERFLOW\n");
					break;
				case EXCEPTION_ILLEGAL_INSTRUCTION:
					write_out(blk->tracefile, "EXCEPTION_ILLEGAL_INSTRUCTION\n");
					break;
				case EXCEPTION_IN_PAGE_ERROR:
					write_out(blk->tracefile, "EXCEPTION_IN_PAGE_ERROR\n");
					break;
				case EXCEPTION_INT_DIVIDE_BY_ZERO:
					write_out(blk->tracefile, "EXCEPTION_INT_DIVIDE_BY_ZERO\n");
					break;
				case EXCEPTION_INT_OVERFLOW:
					write_out(blk->tracefile, "EXCEPTION_INT_OVERFLOW\n");
					break;
				case EXCEPTION_INVALID_DISPOSITION:
					write_out(blk->tracefile, "EXCEPTION_INVALID_DISPOSITION\n");
					break;
				case EXCEPTION_NONCONTINUABLE_EXCEPTION:
					write_out(blk->tracefile, "EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
					break;
				case EXCEPTION_PRIV_INSTRUCTION:
					write_out(blk->tracefile, "EXCEPTION_PRIV_INSTRUCTION\n");
					break;
				case EXCEPTION_SINGLE_STEP:
					write_out(blk->tracefile, "EXCEPTION_SINGLE_STEP\n");
					break;
				case EXCEPTION_STACK_OVERFLOW:
					write_out(blk->tracefile, "EXCEPTION_STACK_OVERFLOW\n");
					break;
				}

				ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, 
								   DBG_EXCEPTION_NOT_HANDLED);
				continue;
			}

			break;

		default:

			write_out(blk->tracefile, "EXCEPTION %08x\n", dbg.dwDebugEventCode);
			break;
		}

		ContinueDebugEvent(dbg.dwProcessId, dbg.dwThreadId, DBG_CONTINUE);
	}
}

/* Publically exported routines. */

void*
NewTrace(void *tracefile, int flags, 
		 unsigned long DebugBlockAddress)
{
	struct trace_block *blk;

	blk = (struct trace_block*)calloc(1, sizeof(struct trace_block));
	if (!blk)
		return NULL;

	if (DebugBlockAddress == 0)
		blk->startblk = 0x40000000;
	else
		blk->startblk = DebugBlockAddress;

	blk->tracefile = tracefile;
	blk->descend = (flags & FLG_DESCEND);
	blk->ShowRetEip = (flags & FLG_INTR_PTR);
	blk->LongLibName = (flags & FLG_LONG_NAME);
	blk->include_ntdll = (flags & FLG_NTDLL);
	blk->hook_count = 1;

	return (void*)blk;
}

void
SpawnTraceProcess(void *trace, char *cmdline)
{
	PROCESS_INFORMATION proc;
	STARTUPINFO startup;
	struct trace_block *blk = (struct trace_block*)trace;

	memset(&startup, 0, sizeof(startup));
	startup.cb = sizeof(startup);

	write_out(blk->tracefile, "Command line:\n\t%s\n", cmdline);

	if (!CreateProcess(NULL, cmdline, NULL, NULL, 
					   FALSE, 
					   CREATE_DEFAULT_ERROR_MODE |
					   CREATE_NEW_CONSOLE |
					   CREATE_NEW_PROCESS_GROUP |
					   DEBUG_PROCESS,
					   NULL, NULL, &startup, &proc))
	{
		WinPerror("Create process failed");
		error("cmdline: %s\n",cmdline);
		exit(1);
	}

	blk->hProcess = proc.hProcess;
	blk->pid = proc.dwProcessId;
	blk->current = TRUE;

	/* Only the thread that created the debugged process can call
	 * WaitForDebugEvent(), so this function *has* to be the one
	 * that calls Trace().
	 */

	Trace(blk);
}

void
TraceProcess(void *trace, DWORD pid)
{
	struct trace_block *blk;

	blk = (struct trace_block*)trace;
	blk->pid = pid;
	blk->hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
								PROCESS_VM_OPERATION |
								PROCESS_VM_READ |
								PROCESS_VM_WRITE |
								SYNCHRONIZE,
								FALSE,
								pid);

	if (blk->hProcess == NULL) 
	{
		WinPerror("OpenProcess()");
		exit(1);
	}

	write_out(blk->tracefile, "Tracing pid %u\n", pid);

	blk->current = TRUE;

	DebugActiveProcess(pid);

	/* Only the thread that created the debugged process can call
	 * WaitForDebugEvent(), so this function *has* to be the one
	 * that calls Trace().
	 */

	Trace(blk);
}

void
StopTracing(void *trace)
{
	struct trace_block *blk;

	blk = (struct trace_block*)trace;

	if (!blk->current)
		return;

	blk = (struct trace_block*)trace;
	blk->libraries_unhooked = FALSE;
	blk->current = FALSE;
}

void
WinPerror(char *message)
{
	DWORD err = GetLastError();
	static char emsg[FORMAT_MESSAGE_MAX_WIDTH_MASK];

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					  NULL, err, 0, emsg, sizeof(emsg), NULL))
	{
		error("%s:%s (%u)\n",message, emsg, err);
	}
	else
	{
		error("%s: Unknown error %u\n", message, err);
	}
}

void 
ReadMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer,
		   DWORD nSize)
{
	DWORD ignored;

	/* All or nothing */

	if (!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &ignored))
	{
		WinPerror("ReadProcessMemory()");
		exit(1);
	}
}

BOOL 
ProtectedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer,
							DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	/* Identical to WriteProcessMemory, only page protections are changed
	 * and reset as needed.
	 */

	if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, 
							nSize, lpNumberOfBytesWritten))
	{
		MEMORY_BASIC_INFORMATION meminfo;

		VirtualQueryEx(hProcess,lpBaseAddress,&meminfo,sizeof(meminfo));

		if ((meminfo.Protect & PAGE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_WRITECOPY) == 0 &&
			(meminfo.Protect & PAGE_EXECUTE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_EXECUTE_WRITECOPY) == 0)
		{
			/* Change the protections, change the data, revert the 
			 * permissions.
			 */
			DWORD old_protection;

			if (!VirtualProtectEx(hProcess, meminfo.BaseAddress, meminfo.RegionSize, 
									  PAGE_READWRITE, &old_protection))
			{
				WinPerror("VirtualProtectEx()");
				return FALSE;
			}

			if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, 
									nSize, lpNumberOfBytesWritten))
			{
#if 1
				VirtualQueryEx(hProcess,lpBaseAddress,&meminfo,sizeof(meminfo));
				error("De-protected write failed:\n");
				error("ADDR %08x\n", lpBaseAddress);
				error("Base addr: %08x\nAlloc Base: %08x\n",
						meminfo.BaseAddress, meminfo.AllocationBase);
				error("Alloc Protection: %x%s%s\n", meminfo.AllocationProtect & 0xff,
						(meminfo.AllocationProtect & PAGE_NOCACHE) ? " | NOCACHE" : "",
						(meminfo.AllocationProtect & PAGE_GUARD) ? " | GUARD" : "");
				error("Region size: %u\nstate: %08x\n",
						meminfo.RegionSize, meminfo.State);
				error("Protection: %x%s%s\n", meminfo.Protect & 0xff,
						(meminfo.Protect & PAGE_NOCACHE) ? " | NOCACHE" : "",
						(meminfo.Protect & PAGE_GUARD) ? " | GUARD" : "");
				error("Type: %08x\n\n",meminfo.Type);
#endif

				return FALSE;
			}
			else
			{
				DWORD bogus;

				/* Change back */

				if (!VirtualProtectEx(hProcess, meminfo.BaseAddress, meminfo.RegionSize, 
									 old_protection, &bogus))
					WinPerror("VirtualProtectEx(revert)");
			}

		} /* meminfo.Protect */
		else
			return FALSE;

	} /* !WriteProcessMemory() */

	return TRUE;
}

/* $Id: ptrace.c,v 1.12 2002/11/23 08:14:29 john Exp $ -- EOF */
