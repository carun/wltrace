#ifndef _COMMANDS_H
#define _COMMANDS_H

#include <pshpack1.h>

struct TraceCommand {
	DWORD Pid;
	DWORD Flags;
	DWORD NumHooks;
	char OutputFile[1];
	/* Hooks */
};

#include <poppack.h>

extern BOOL ProcessCommand(struct Connection*, char*, int);

#endif /* _COMMANDS_H */

