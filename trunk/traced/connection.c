/* Connection.c
 */

#include <winsock2.h>
#include <stdio.h>
#include "connection.h"
#include "ptrace.h"
#include "write.h"

unsigned int MaxEvents;
WSAEVENT EventList[MAX_CONNECTIONS + 2];
struct Connection *EventOwners[MAX_CONNECTIONS + 2];

static struct Connection ConnectionList[MAX_CONNECTIONS];
static struct Connection *FreeSlots, *BusySlots;

void ArrangeEvents(void);

void
InitConnectionList(void)
{
	int i;

	ConnectionList[0].Index = 0;

	for(i=0;i<MAX_CONNECTIONS;i++)
	{
		ConnectionList[i].Index = i;
		ConnectionList[i].State = TRACE_FREE;
		if (i)
			ConnectionList[i-1].Next = &ConnectionList[i];
	}

	ConnectionList[i].Next = NULL;
	FreeSlots = &ConnectionList[0];
	BusySlots = NULL;
}

struct Connection *
GetFreeConn(void)
{
	struct Connection *Slot;

	if ((Slot = FreeSlots) != NULL)
	{
		FreeSlots = FreeSlots->Next;
	}

	memset(Slot, 0, sizeof(*Slot));

	Slot->ChildSocket = INVALID_SOCKET;
	Slot->State = TRACE_CONFIG;
	Slot->Next = BusySlots;
	BusySlots = Slot;

	return Slot;
}

void
RecycleConn(struct Connection *Slot)
{
	struct Connection **cptr;
	BOOL Found = FALSE;

#ifdef _DEBUG
	fprintf(stderr, "Recycling trace block\n");
#endif

	for(cptr = &BusySlots; *cptr != NULL; cptr = &(*cptr)->Next)
	{
		if ((*cptr)->Index == Slot->Index)
		{
			Found = TRUE;
			break;
		}
	}

	if (!Found)
	{
		error("HELP! RecycleConn() called on Slot not present in busy list!\n");
		return;
	}

	/* Generic shutdown code */

	if (Slot->ChildSocket != INVALID_SOCKET)
	{
		shutdown(Slot->ChildSocket, SD_BOTH);
		closesocket(Slot->ChildSocket);
		Slot->ChildSocket = INVALID_SOCKET;

		if (Slot->ChildSockEvent != WSA_INVALID_EVENT)
		{
			WSACloseEvent(Slot->ChildSockEvent);
			Slot->ChildSockEvent = WSA_INVALID_EVENT;
		}
	}

	if (Slot->StopTracingEvent != NULL)
	{
		CloseHandle(Slot->StopTracingEvent);
		if (Slot->StopTracingEventName != NULL)
		{
			free(Slot->StopTracingEventName);
			Slot->StopTracingEventName = NULL;
		}
	}

#ifdef _DEBUG
	switch(Slot->State)
	{
	case TRACE_TRACING:
		puts("tracing->idle");
		break;

	case TRACE_IDLE:
		puts("idle->free");
		break;

	case TRACE_CONFIG:
		puts("config->free");
		break;

	case TRACE_FREE:
		puts("free->free");
		break;
	}
#endif

	switch(Slot->State)
	{
	case TRACE_TRACING:

		StopTracing(Slot->TraceBlock);
		Slot->State = TRACE_IDLE;
		break;

	case TRACE_IDLE:

		CloseHandle(Slot->ThreadHandle);

		/* fall through */

	case TRACE_CONFIG:

		Slot->State = TRACE_FREE;

		/* fall through */

	case TRACE_FREE:

		/* Remove from busy list */
		*cptr = (*cptr)->Next;

		/* Add to free list */
		Slot->Next = FreeSlots;
		FreeSlots = Slot;
		break;
	}

	ArrangeEvents();
}

void
ArrangeEvents(void)
{
	struct Connection *cptr;
	int i;

	for(i = 2, cptr = BusySlots; cptr != NULL; cptr = cptr->Next, i++)
	{
		switch(cptr->State)
		{
		case TRACE_CONFIG:
			EventList[i] = cptr->ChildSockEvent;
			break;

		case TRACE_TRACING:
			EventList[i] = cptr->StopTracingEvent;
			break;

		case TRACE_IDLE:
			EventList[i] = cptr->ThreadHandle;
			break;

		case TRACE_FREE:
			error("Connection with state TRACE_FREE found on busy list!\n");
			return;
		}

		EventOwners[i] = cptr;
	}

	MaxEvents = i;

	for(cptr = FreeSlots; cptr != NULL; cptr = cptr->Next, i++);

	if (i != MAX_CONNECTIONS + 2)
	{
		error("Help! We've lost %i slots!\n", MAX_CONNECTIONS + 2 - i);
	}
}

void
StopAllTracers(void)
{
	struct Connection *cptr;

	for(cptr = BusySlots; cptr != NULL; cptr = cptr->Next)
	{
		RecycleConn(cptr);
	}
}

/* $Id: connection.c,v 1.5 2002/11/17 23:44:16 john Exp $ -- EOF */
