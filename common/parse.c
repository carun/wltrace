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

/* Config file parsing routines.
 * Configfile consists of declarations conforming to the following
 * format:
 *
 * <dllname>:
 * <function>(<direction><type1> [, <direction><type2> [...]])
 *
 * Where <direction> is on of:
 *
 *	in			decode parameter on function entry.
 *
 *	out			decode parameter on function exit.
 *
 *	inout		decode parameter on function entry, and on function exit.
 *
 *
 * <callspec> is one of:
 *
 *	cdecl		Default calling method. Parameters pushed onto
 *			stack from right to left. 
 *
 *	fastcall	Registers ECX & EDX hold first 2 arguments,
 *			the rest are pushed on the stack from right
 *			to left. 
 *
 *	stdcall		Parameters are pushed on the stack from right
 *			to left. 
 *
 * NOTE: WINAPI is a synonym for cdecl. NTAPI is a synonym for stdcall.
 *
 * The routines in this file are NOT thread-safe. It is envisaged that dll_list 
 * is a global, read-only list constructed during tracer initialisation (ie
 * remote debug clients do not provide a per-tracee functions file).
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include "parse.h"
#include "ptrace.h"
#include "write.h"

static char*
strtok_r(char *line, const char *delimiters, char **marker)
{
	char *rptr, *p;

	if (line != NULL)
		p = line;
	else if ((p = *marker) == NULL)
		return NULL;

	while(*p && strchr(delimiters, *p))
		*p++ = '\0';

	if (!*p)
	{
		*marker = NULL;
		return NULL;
	}

	rptr = p;
	while(strchr(delimiters, *p) == NULL)
		p++;

	*p++ = '\0';
	*marker = p;

	return rptr;
}

static char*
next_token(char *line)
{
	static char *previous_token = NULL, *pptr = NULL;
	static char special[1024] = "";
	char *rptr;

	if (line) 
		previous_token = strtok_r(line, " \t\r\n", &pptr);

	if (previous_token == NULL)
	{
		previous_token = strtok_r(NULL, " \t\r\n", &pptr);
		if (previous_token == NULL)
			return NULL;
	}

	if (strchr("(),*:", *previous_token))
	{
		special[0] = *previous_token++;
		special[1] = '\0';

		if (!*previous_token)
			previous_token = NULL;

		return special;
	}


	rptr = previous_token;
	while(*rptr)
	{
		if (strchr("(),*:", *rptr))
		{
			strncpy(special, previous_token, (int)(rptr - previous_token));
			special[(int)(rptr - previous_token)] = '\0';
			previous_token = rptr;
			return special;
		}
		else
			rptr++;
	}

	rptr = previous_token;
	previous_token = NULL;
	return rptr;
}

struct dll_spec *dll_list = NULL;

int
strficmp(char *n1, char *n2)
{
	char *p = strrchr(n1, '\\');
	char *q = strrchr(n2, '\\');

	if (p == NULL || q == NULL)
	{
		p = (p ? (p+1) : n1);
		q = (q ? (q+1) : n2);
	}
	else
	{
		p = n1;
		q = n2;
	}

	return stricmp(p, q);
}

struct dll_spec *
find_dll(char *name)
{
	struct dll_spec *p = dll_list;

	/* Both p->name and dll can be either base filenames,
	 * or full pathnames. Ensure that we only compare the last
	 * components (ie 2 basenames) unless both p->name and 
	 * dll are full pathnames.
	 */

	while(p)
	{
		if (!strficmp(p->name, name))
			return p;
		else 
			p = p->next;
	}

	return NULL;
}

struct fn_spec *
find_fn(struct dll_spec *dll, char *name)
{
	struct fn_spec *p = dll->fns;

	while(p)
	{
		if (!stricmp(p->name, name))
			return p;
		else p = p->next;
	}

	return NULL;
}

static struct dll_spec *
new_dll(char *name)
{
	struct dll_spec *r = (struct dll_spec*)calloc(1,sizeof(*r));

	if (!r)
	{
		perror("malloc");
		exit(1);
	}

	r->name = name;
	r->next = dll_list;
	dll_list = r;

	return r;
}

static struct fn_spec *
new_fn(struct dll_spec *parent, char *name, int line_no, int cc)
{
	struct fn_spec *r = (struct fn_spec*)calloc(1,sizeof(*r));

	if (!r)
	{
		perror("malloc");
		exit(1);
	}

	r->name = name;
	r->dll = parent;
	r->line_no = line_no;
	r->call_convention = cc;
	r->next = parent->fns;
	parent->fns = r;

	return r;
}

extern struct type_defn types_list[];

int
parse_config(char *config_file)
{
	FILE *fd;
	char linebuf[1024], *token, *fn_name;
	int line_no = 1;
	struct dll_spec *current_dll = NULL;
	struct fn_spec *f;

	if (!config_file)
	{
		error("Missing name of config file to parse\n");
		return -1;
	}

	if ((fd = fopen(config_file, "r")) == NULL)
	{
		perror(config_file);
		return -1;
	}

	while(fgets(linebuf, sizeof(linebuf), fd) != NULL)
	{
		int call_convention = STDCALL, arg_count = 1, out_arg_count = 0;
		struct param *param_list_head = NULL;

		token = next_token(linebuf); 
		if (!token) 
		{
			line_no++;
			continue;
		}

		if (!stricmp(token,"fastcall"))
		{
			call_convention = FASTCALL;
			token = next_token(NULL);
		}
		else if (stricmp(token, "cdecl") == 0 || 
				 stricmp(token, "stdcall") == 0)
		{
			token = next_token(NULL);
		}

		if (token == NULL)
			goto truncated;

		fn_name = strdup(token);

		token = next_token(NULL);
		if (*token == ':')
		{
			/* DLL containing following function specs is specified:
			 *	DLL_NAME :
			 */

			current_dll = find_dll(fn_name);
			if (current_dll)
			{
				free(fn_name);
			}
			else
			{
				current_dll = new_dll(fn_name);
			}

			/* ignore the rest of the line. */
			line_no++;
			continue;
		}

		/* else fn_name is the name of a function. */

		f = find_fn(current_dll,fn_name);
		if (f != NULL)
		{
			error("Duplicate function found on line %u of %s (previously defined on line %u)\n",
					line_no, config_file, f->line_no);
			return -1;
		}

		f = new_fn(current_dll, fn_name, line_no, call_convention);

		if (*token != '(')
		{
			error("Expected '(' after %s on line %u of %s\n",
					fn_name, line_no, config_file);
			return -1;
		}

		while((token = next_token(NULL)) != NULL)
		{
			struct param param, *this_param;
			struct type_defn *t;

			if (*token == ')')
				break;

			/* <direction><type> [, <direction><type> ...] 
			 * 
			 * See types.c for a valid list of types.
			 */

			if (!stricmp(token, "in"))
			{
				param.direction = IN_ARG;
			}
			else if (!stricmp(token, "out"))
			{
				param.direction = OUT_ARG;
				out_arg_count++;
			}
			else if (!stricmp(token, "inout"))
			{
				param.direction = INOUT_ARG;
				out_arg_count++;
			}
			else
			{
				error(
					"Unrecognised argument direction %s in line %u of %s"
					"(expected IN, OUT, or INOUT)\n",
					token, line_no, config_file);
				return -1;
			}

			param.type = NULL;

			if ((token = next_token(NULL)) == NULL)
			{
				error("Missing argument type in line %u of %s\n",
						line_no, config_file);
				return -1;
			}

			for(t = types_list; t->type_name != NULL; t++)
			{
				if (!strcmp(t->type_name, token))
				{
					param.type = t;
					break;
				}
			}

			if (param.type == NULL)
			{
				error("Unrecognised type %s in line %u of %s\n",
						token, line_no, config_file);
				return -1;
			}

			/* add param */

			if ((this_param = (struct param*)calloc(1,sizeof(*this_param))) == NULL)
			{
				perror("malloc");
				exit(1);
			}

			memcpy(this_param,&param,sizeof(param));
			this_param->next = NULL;

			if (!param_list_head)
			{
				param_list_head = f->params = this_param;
			}
			else
			{
				param_list_head->next = this_param;
				param_list_head = this_param;
			}

			f->n_args = arg_count;
			f->n_out_args = out_arg_count;

			token = next_token(NULL);
			if (token)
			{
				if (*token == ')')
					break;
				else if (*token == ',')
				{
					arg_count++;
					continue;
				}
				else 
				{
					error(
							"Expected ')' or ',' after arg %u on line %u of %s\n",
							arg_count, line_no, config_file);
					return -1;
				}
			}
			else
				goto truncated;
		}

		if (!token)
			goto truncated;

		if (*token != ')')
		{
			error("Expected '(', but found %s on line %u of %s\n",
					token, line_no, config_file);
			return -1;
		}

		line_no++;
		continue;

truncated:
		error("Truncated entry on line %u of %s\n",
				line_no, config_file);
		return -1;
	}

	fclose(fd);

	return 0;
}

