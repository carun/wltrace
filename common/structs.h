#ifndef _INTERNAL_STRUCTS_H
#define _INTERNAL_STRUCTS_H

/* ptrace.h */

struct library;

struct export_entry {
	char *name;
	LPVOID orig_addr;
	LPVOID new_addr;
	BOOL forwarder;
	struct {
		struct library *lib;
		BOOL is_ordinal;
		union {
			WORD ordinal;
			char *symbol;
		} u;
	} fwdr_info;
	struct library *parent;
};

struct link {
	struct library *referer;
	DWORD import_lookup_table;
	DWORD iat;
	struct link *next;
};

struct library {
	char *name;
	MODULEINFO libinfo;
	BOOL valid;
	struct export_entry *export_table;
	int export_table_sz;
	DWORD export_ordinal_base;
	struct link *dependency_list;
	struct library *next;
};

struct call_frame {
	DWORD original_ret_eip;
	struct export_entry *caller;
	struct {
		BOOL flagged;
		struct export_entry *proc;
	} proc_address;
	struct call_frame *next;
};

struct child_thread {
	HANDLE thread_handle;
	DWORD thread_id;
	int is_master;
	struct call_frame *call_stack;
	struct child_thread *next;
};

/* Hookpattern.h */

struct fn_hook {
	char *function;
	int ordinal;
	BOOL is_ordinal;
	struct fn_hook *next;
};

struct lib_hook {
	char *name;
	BOOL all_functions;
	struct fn_hook *functions;
	struct lib_hook *next;
};

struct exe_hook {
	char *exe;
	struct lib_hook *libs;
	struct exe_hook *next;
};


struct trace_block
{
	BOOL current;
	BOOL libraries_unhooked;

	LPVOID brkpnt_blk;
	DWORD brkpnt_blksz;
	DWORD startblk;		

	struct library *library_list;
	struct export_entry **int3_deref;

	BOOL descend;
	BOOL ShowRetEip;
	BOOL LongLibName;
	BOOL include_ntdll;
	FILE *tracefile;

	HANDLE hProcess;
	DWORD pid;

	struct child_thread *thread_list;
	DWORD hook_count;
	struct exe_hook *hook_patterns;
	struct exe_hook *default_pattern;

	struct trace_block *next;
};

#endif /* _INTERNAL_STRUCTS_H */

/* $Id: structs.h,v 1.5 2002/11/23 08:14:29 john Exp $ -- EOF */
