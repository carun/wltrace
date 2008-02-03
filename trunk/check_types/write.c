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

#include <stdio.h>
#include <stdarg.h>

void
error(char *message, ...)
{
	va_list Args;

	va_start(Args, message);
	vfprintf(stderr, message, Args);
	va_end(Args);
}

int
write_out(void *stream, char *format, ...)
{
	va_list Args;
	int rv;

	va_start(Args, format);
	rv = vfprintf(stderr, format, Args);
	va_end(Args);

	return rv;
}

/* $Id: write.c,v 1.1 2002/11/23 09:22:32 john Exp $ -- EOF */
