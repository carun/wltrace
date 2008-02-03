#include <windows.h>
#include <stdio.h>
#include "parse.h"
#include "types.h"

int
main(int argc, char **argv)
{

	if (argc > 1)
	{
		parse_config(argv[1]);
	}
	else
	{
		char SysDir[1024];
		GetSystemDirectory(SysDir, sizeof(SysDir));

		strcat(SysDir, "\\decode.txt");

		parse_config(SysDir);
	}

	return 0;
}

/* $Id: check.c,v 1.1 2002/11/23 09:22:32 john Exp $ -- EOF */
