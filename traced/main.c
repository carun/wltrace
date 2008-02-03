#include <winsock2.h>
#include <stdio.h>
#include <assert.h>
#include <aclapi.h>
#include "service.h"
#include "ptrace.h"
#include "parse.h"
#include "connection.h"
#include "commands.h"
#include "write.h"

int debug = 0;
SOCKET TracePort;
HANDLE ShutdownEvent;

BOOL 
SetPrivilege(HANDLE hToken,LPCTSTR lpszPrivilege,BOOL bEnablePrivilege) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if ( !LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) 
	{
		WinPerror("LookupPrivilegeValue error"); 
		return FALSE; 
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
	{
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}
	else
	{
		tp.Privileges[0].Attributes = 0;
	}

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), 
						  (PTOKEN_PRIVILEGES) NULL, (PDWORD) NULL); 
 
	if (GetLastError() != ERROR_SUCCESS) 
	{ 
		WinPerror("AdjustTokenPrivileges failed");
		return FALSE; 
	} 

	return TRUE;
}

HANDLE
MakeEvent(char **EventName)
{
	char Name[128], AclBuf[256];
	static int EventCount = 0;
	HANDLE Event;
	PACL Acl;
	SID World = { SID_REVISION, 1, SECURITY_WORLD_SID_AUTHORITY, SECURITY_WORLD_RID };

	sprintf(Name, "Traced_%lu_%lu", GetCurrentProcessId(), EventCount++);
	*EventName = strdup(Name);

	Event = CreateEvent(NULL, TRUE, FALSE, Name);
	if (Event == NULL)
		return Event;

	Acl = (PACL)AclBuf;
	InitializeAcl(Acl, sizeof(AclBuf), ACL_REVISION);
	AddAccessAllowedAce(Acl, ACL_REVISION, EVENT_MODIFY_STATE, &World);

	if (SetSecurityInfo(Event, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, 
						Acl, NULL) != ERROR_SUCCESS)
	{
		error("SetSecurityInfo() failed!\n");
		CloseHandle(Event);
		return NULL;
	}

	return Event;
}

DWORD 
InitialiseService(void)
{
	WSADATA WinsData;
	struct sockaddr_in addr;
	HANDLE ptoken;

	InitConnectionList();

	if (WSAStartup(MAKEWORD(2,0), &WinsData))
		return GetLastError();

	TracePort = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (TracePort == INVALID_SOCKET)
		return WSAGetLastError();

	addr.sin_family = AF_INET;
	addr.sin_port = htons(7000);
	addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(TracePort, (struct sockaddr*)&addr, sizeof(addr)))
	{
		closesocket(TracePort);
		return WSAGetLastError();
	}

	listen(TracePort, 5);

	EventList[1] = WSACreateEvent();

	if (EventList[1] == WSA_INVALID_EVENT)
	{
		closesocket(TracePort);
		return WSAGetLastError();
	}

	if (WSAEventSelect(TracePort, EventList[1], FD_ACCEPT))
	{
		closesocket(TracePort);
		WSACloseEvent(EventList[1]);
		return WSAGetLastError();
	}

	EventList[0] = CreateEvent(NULL, TRUE, FALSE, NULL);

	if (EventList[0] == NULL)
	{
		WinPerror("CreateEvent()");
		return GetLastError();
	}

	ArrangeEvents();

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
						  &ptoken))
	{
		WinPerror("OpenProcessToken() failed");
		return GetLastError();
	}

	if (!SetPrivilege(ptoken,"SeDebugPrivilege",TRUE))
	{
		WinPerror("Failed to grant myself SeDebugPrivilege");
		return GetLastError();
	}

	{
		char SysDir[1024];
		GetSystemDirectory(SysDir, sizeof(SysDir));

		strcat(SysDir, "\\decode.txt");

		if (parse_config(SysDir))
		{
			error("Failed to parse config file.\n");
			return GetLastError();
		}
	}

#ifdef _DEBUG
	fputs("InitialiseService() complete successfully\n", stderr);
#endif

	return 0L;
}

/* Accept	->	BusyList, TRACE_CONFIG
 * Read		->	BusyList, TRACE_TRACING
 * Event	->	IdleList, TRACE_IDLE
 * Exit		->	FreeList, TRACE_FREE
 */

void 
RunService(void)
{
	struct sockaddr_in ChildAddr;
	struct Connection *Child;
	SOCKET ChildSock;
	WSAEVENT ChildSockEvent;
	int ChildAddrSz;
	DWORD i;
	static blah;

#ifdef _DEBUG
	fputs("RunService() starting\n", stderr);
#endif

	while(1)
	{
		DWORD Status;

		Status = WSAWaitForMultipleEvents(MaxEvents, EventList, FALSE, INFINITE, FALSE);

		if (Status == -1)
		{
			/* Error in service, service will shutdown gracefully on return */
			return;
		}

		if (Status == WSA_WAIT_EVENT_0)
		{
			/* shutdown */
			break;
		}

		if (Status == (WSA_WAIT_EVENT_0 + 1))
		{
			/* Connection pending */

			ResetEvent(EventList[1]);

			ChildAddr.sin_family = AF_INET;
			ChildAddr.sin_addr.s_addr = INADDR_ANY;
			ChildAddr.sin_port = 0;

			ChildAddrSz = sizeof(ChildAddr);

			ChildSock = accept(TracePort, (struct sockaddr*)&ChildAddr, &ChildAddrSz);

			if (ChildSock == INVALID_SOCKET)
			{
				continue;
			}

			ChildSockEvent = WSACreateEvent();

			if (ChildSockEvent == INVALID_SOCKET)
			{
				closesocket(ChildSock);
				continue;
			}

			if (WSAEventSelect(ChildSock, ChildSockEvent, FD_READ | FD_CLOSE) == SOCKET_ERROR)
			{
				closesocket(ChildSock);
				WSACloseEvent(ChildSockEvent);
				continue;
			}

			if ((Child = GetFreeConn()) == NULL)
			{
				closesocket(ChildSock);
				WSACloseEvent(ChildSockEvent);
				continue;
			}

			Child->ChildSocket = ChildSock;
			Child->ChildSockEvent = ChildSockEvent;
			Child->StopTracingEvent = MakeEvent(&Child->StopTracingEventName);

			if (Child->StopTracingEvent == NULL)
			{
				RecycleConn(Child);
				continue;
			}

			ArrangeEvents();
			continue;
		}

		/* Status in range WSA_WAIT_EVENT_0 + 2 ... WSA_WAIT_EVENT_0 + MAX_CONNECTIONS */

		i = Status - WSA_WAIT_EVENT_0;

		if (EventOwners[i]->State == TRACE_TRACING)
		{
			/* Shutdown event */
#ifdef _DEBUG
			fputs("Stopping trace\n", stderr);
#endif
			ResetEvent(EventOwners[i]->StopTracingEvent);
			fclose(EventOwners[i]->OutputFile);
			EventOwners[i]->OutputFile = NULL;
			RecycleConn(EventOwners[i]);
			continue;
		}

		if (EventOwners[i]->State == TRACE_IDLE)
		{
			/* Event has exitted, cleanup */
			RecycleConn(EventOwners[i]);
			continue;
		}

		assert(EventOwners[i]->State == TRACE_CONFIG);

		for( ; i < MaxEvents; i++)
		{
			WSANETWORKEVENTS EventMenu;

			WSAEnumNetworkEvents(EventOwners[i]->ChildSocket, EventList[i], &EventMenu);
			WSAResetEvent(EventList[i]);

			if (EventMenu.lNetworkEvents & FD_CLOSE)
			{
				RecycleConn(EventOwners[i]);
				continue;
			}
			else if (EventMenu.lNetworkEvents & FD_READ)
			{
				char ReadBuffer[1024];
				int ReadLength;

				if (EventMenu.iErrorCode[FD_READ_BIT] != ERROR_SUCCESS)
				{
					RecycleConn(EventOwners[i]);
					continue;
				}

				ReadLength = recv(EventOwners[i]->ChildSocket, ReadBuffer, sizeof(ReadBuffer), 0);
				if (ReadLength < 0)
				{
					RecycleConn(EventOwners[i]);
					continue;
				}

				if (EventOwners[i]->State == TRACE_CONFIG)
				{
					if (!ProcessCommand(EventOwners[i], ReadBuffer, ReadLength))
					{
						send(EventOwners[i]->ChildSocket, "Bad options\r\n", 11, 0);
						RecycleConn(EventOwners[i]);
					}
				}
			}

		} /* for(;i;) */

	} /* while(1) */

#ifdef _DEBUG
	fputs("RunService() completing\n", stderr);
#endif
}

void 
CleanupService(void)
{
	StopAllTracers();
}

void 
InterruptService(void)
{
	SetEvent(EventList[0]);
}

int
main()
{
	SetServiceName("traced");
	Execute();
	exit(0);
}

