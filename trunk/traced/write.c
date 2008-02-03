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

#include <winsock2.h>
#include <stdio.h>
#include <stdarg.h>
#include "connection.h"
#include "eventlog.h"

static HANDLE EventSource = NULL;

void
error(char *Format, ...)
{
	char ErrorFormatString[1024];
	char ErrorMessage[FORMAT_MESSAGE_MAX_WIDTH_MASK];
	char *InPtr, *OutPtr, *End;
	va_list Arguments;
#ifndef _DEBUG
	char ErrorMessageBuffer[1024], *Args[2];
#endif

	/* Expand '%m' escapes into a readable error message. */

	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_MAX_WIDTH_MASK,
					  NULL, GetLastError(), 0, ErrorMessage, sizeof(ErrorMessage), NULL) == 0)
	{
		_snprintf(ErrorMessage, sizeof(ErrorMessage), "Error %lu", GetLastError());
	}

	InPtr = Format; 
	OutPtr = ErrorFormatString;
	End = ErrorFormatString + sizeof(ErrorFormatString) - 1;

	while((*InPtr != '\0') && (OutPtr != End))
	{
		*OutPtr = *InPtr++;

		if (InPtr[-1] == '%')
		{
			if (InPtr[0] != 'm')
			{
				OutPtr++;
				continue;
			}

			*OutPtr = '\0';
			strncat(ErrorFormatString, ErrorMessage, sizeof(ErrorFormatString) - strlen(ErrorFormatString));
			OutPtr = ErrorFormatString + strlen(ErrorFormatString);
		}
		else
		{
			OutPtr++;
		}
	}

	/* Format all other args in the normal way. */

#ifdef _DEBUG
	va_start(Arguments, Format);
	vfprintf(stderr, Format, Arguments);
	va_end(Arguments);
#else
	va_start(Arguments, Format);
	_vsnprintf(ErrorMessageBuffer, sizeof(ErrorMessageBuffer), ErrorFormatString, Arguments);
	va_end(Arguments);

	if (EventSource == NULL) 
	{
		EventSource = RegisterEventSource(NULL, "traced");
		if (EventSource == NULL)
			fprintf(stderr,"Register failed %u\n", GetLastError());
	}

	Args[0] = ErrorMessageBuffer;

	ReportEvent(EventSource, 
				EVENTLOG_ERROR_TYPE, 
				0,
				MSG_GENERIC_ERROR,
				NULL,					// User security descriptor
				1,						// Number of strings
				0,						// Size of contextual data
				(const char **)Args,
				NULL);					// Contextual data
#endif
}

int
write_out(void *stream, char *format, ...)
{
	struct Connection *Conn;
	FILE *tracefile;
	va_list Args;
	int rv;

	Conn = (struct Connection*)stream;
	tracefile = Conn->OutputFile;

	if (tracefile != NULL)
	{
		va_start(Args, format);
		rv = vfprintf(tracefile, format, Args);
		va_end(Args);
		fflush(tracefile);
	}

	return rv;
}

/* $Id: write.c,v 1.5 2002/11/19 03:44:04 john Exp $ -- EOF */
