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

#ifndef _PARSE_H
#define _PARSE_H

enum {
	STDCALL,
	FASTCALL
}; 

enum {
	IN_ARG,
	OUT_ARG,
	INOUT_ARG
};

#ifdef TYPE_NAMES_ONLY
typedef char ContentHandler[1];

struct type_defn 
{
	char *type_name;
	void *content_handler;
};

#else
typedef char *(ContentHandler)(DWORD*, struct param*, HANDLE, int);

struct type_defn 
{
	char *type_name;
	ContentHandler *content_handler;
};
#endif

struct param
{
	struct type_defn *type;
	int direction;
	struct param *next;
};

struct dll_spec;

struct fn_spec
{
	char *name;
	int call_convention;
	int line_no;			/* for error messages */
	struct param *params;
	int n_args;
	int n_out_args;
	struct dll_spec *dll;
	struct fn_spec *next;
};

struct dll_spec 
{
	char *name;
	struct fn_spec *fns;
	struct dll_spec *next;
};


extern struct dll_spec *dll_list;

extern int parse_config(char*);
extern struct dll_spec *find_dll(char*);
extern struct fn_spec *find_fn(struct dll_spec*,char*);
extern int strficmp(char*, char*);

#endif /* _PARSE_H */



