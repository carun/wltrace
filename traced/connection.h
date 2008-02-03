#ifndef _TRACED_H
#define _TRACED_H

#define MAX_CONNECTIONS (MAXIMUM_WAIT_OBJECTS - 2)

typedef enum {
	TRACE_CONFIG,
	TRACE_TRACING,
	TRACE_IDLE,
	TRACE_FREE
} TracerState;

struct Connection
{
	TracerState State;

	SOCKET ChildSocket;
	WSAEVENT ChildSockEvent;
	void *TraceBlock;

	int Index;

	DWORD TracedProcess;

	HANDLE ThreadHandle;
	DWORD ThreadId;

	HANDLE StopTracingEvent;
	char *StopTracingEventName;

	unsigned long Flags;
	FILE *OutputFile;

	struct Connection *Next;
};

extern unsigned int MaxEvents;
extern WSAEVENT EventList[];
extern struct Connection *EventOwners[];

extern void InitConnectionList(void);
extern struct Connection *GetFreeConn(void);
extern void RecycleConn(struct Connection*);
extern void StopAllTracers(void);
extern void ArrangeEvents(void);

#endif /* _TRACED_H */
