
#include <winsock2.h>
#include <stdio.h>
#include "ptrace.h"
#include "connection.h"
#include "commands.h"
#include "print.h"
#include "write.h"
#include "hookpattern.h"

extern int debug;

DWORD WINAPI 
StartTrace(struct Connection *Tracer)
{
	TraceProcess(Tracer->TraceBlock, Tracer->TracedProcess);

	/* Ugly hack alert: We need to notify the parent thread that we have exitted.
	 * We do this by closing the socket, which causes the connection struct to
	 * be added to the idle list, at which point the death of the thread will
	 * immediately be noticed.
	 */
	closesocket(Tracer->ChildSocket);
	return 0L;
}

BOOL
DoTraceables(void *tracer, char *arg)
{
	char *dll, *lib, *fn, *d;

	dll = arg;
	d = strchr(dll, ':');
	if (d == NULL)
		return FALSE;

	*d++ = '\0';
	if (*dll == '\0')
		dll = NULL;

	lib = d;
	d = strchr(lib, ':');
	if ((d == NULL) || (*d == '\0'))
		return FALSE;

	*d++ = '\0';
	fn = d;
	if (*fn == '\0')
		fn = NULL;

	if (SetHookPattern(tracer, dll, lib, fn)) 
	{
		error("Conflicting pattern '%s:%s:%s'\n", 
				dll ? dll : "", lib, fn ? fn : "");
		return FALSE;
	}

	return TRUE;
}

BOOL 
ProcessCommand(struct Connection *Tracer, char *Buffer, int BufferLength)
{
	struct TraceCommand *cmd = (struct TraceCommand*)Buffer;
	int Consumed;

	Tracer->Flags = ntohl(cmd->Flags);
	debug = (Tracer->Flags & FLG_DEBUG);

	if (debug) error("DEBUGing enabled");

	Tracer->TracedProcess = ntohl(cmd->Pid);
	Tracer->OutputFile = fopen(cmd->OutputFile, "w");

	if (Tracer->OutputFile == NULL)
	{
		return FALSE;
	}

#ifdef _DEBUG
	fprintf(stderr, "Creating trace block\n");
#endif

	Tracer->TraceBlock = NewTrace(Tracer, Tracer->Flags, 0);
	if (Tracer->TraceBlock == NULL)
	{
		return FALSE;
	}

	Consumed = sizeof(*cmd) + strlen(cmd->OutputFile);
	Buffer += Consumed;

	while(Consumed < BufferLength)
	{
		int len = strlen(Buffer) + 1;

#ifdef _DEBUG
		fprintf(stderr, "Trace hook: %s\n", Buffer);
#endif

		if (!DoTraceables(Tracer->TraceBlock, Buffer)) 
		{
			return FALSE;
		}
		Consumed += len;
		Buffer += len;
	}

#ifdef _DEBUG
	fprintf(stderr, "Creating trace thread\n");
#endif

	Tracer->ThreadHandle = CreateThread(NULL, 0, StartTrace, (LPTHREAD_START_ROUTINE)Tracer,
										0, &Tracer->ThreadId);

	if (Tracer->ThreadHandle == NULL)
	{
		return FALSE;
	}

	if ((unsigned)send(Tracer->ChildSocket, Tracer->StopTracingEventName, strlen(Tracer->StopTracingEventName) + 1, 0) != strlen(Tracer->StopTracingEventName) + 1)
	{
		return FALSE;
	}

	Tracer->State = TRACE_TRACING;

	return TRUE;
}

/* $Id: commands.c,v 1.7 2003/02/05 05:49:49 john Exp $ -- EOF */
