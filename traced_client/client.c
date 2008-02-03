#include <winsock2.h>
#include <stdio.h>
#include "connection.h"
#include "commands.h"
#include "ptrace.h"

extern void ShowDeps(char *filename);

HANDLE Shutdown;

static BOOL WINAPI 
ControlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType)
	{
	case CTRL_BREAK_EVENT:
	case CTRL_C_EVENT:

		SetEvent(Shutdown);
		Sleep(1000);
		exit(0);

	default:
		break;
	}

	return FALSE;
}

void
usage(char *argv0)
{
	fprintf(stderr, "%s [-dlvi] output_filename pid [tracehook [...]]\n", argv0);
	fprintf(stderr, "%s -a exe\n", argv0);
	exit(1);
}

int
main(int argc, char **argv)
{
	int i, len, flags;
	SOCKET sock;
	WSADATA winsdata;
	struct TraceCommand *Cmd;
	char buf[2048];
	struct sockaddr_in addr;

	flags = 0;

	for(i=1;i<argc;i++)
		if (*argv[i] == '-')
		{
			switch(argv[i][1]) {
			case 'd':
				flags |= FLG_DESCEND;
				break;

			case 'i':
				flags |= FLG_INTR_PTR;
				break;

			case 'l':
				flags |= FLG_LONG_NAME;
				break;

			case 'n':
				flags |= FLG_NTDLL;
				break;

			case 'v':
				flags |= FLG_DEBUG;
				break;

			case 'a':
				if (++i >= argc)
				{
					usage(argv[0]);
				}

				ShowDeps(argv[i]);
				exit(0);
			}
		}
		else
			break;

	if ((argc - i) < 2)
	{
		usage(argv[0]);
	}

	if (WSAStartup(MAKEWORD(2,0), &winsdata))
	{
		fprintf(stderr, "WSAStartup() failed\n");
		exit(1);
	}

	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		fprintf(stderr, "socket() failed\n");
		exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(7000);

	if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)))
	{
		fprintf(stderr, "connect() failed\n");
		exit(1);
	}

	Cmd = (struct TraceCommand*)buf;

	Cmd->Flags = htonl(flags);

	Cmd->Pid = htonl(atoi(argv[i+1]));
	strcpy(Cmd->OutputFile, argv[i]);

	len = sizeof(*Cmd) + strlen(argv[i]);

	i += 2;

	while(i < argc)	
	{
		unsigned int hook_len = strlen(argv[i])+1;
		if ((sizeof(buf) - len) < hook_len)
		{
			fprintf(stderr, "Too much data (buffer %u bytes in size, %u bytes used, %i bytes left\n",
					sizeof(buf),len, (sizeof(buf)-len));
			exit(1);
		}
		memcpy(&buf[len], argv[i], hook_len);
		len += hook_len;
		i++;
	}

	if (send(sock, buf, len, 0) != len)
	{
		fprintf(stderr, "Send command failed\n");
		exit(1);
	}

	len = recv(sock, buf, sizeof(buf), 0);

	printf("Shutdown event is called %s\n", buf);

	Shutdown = OpenEvent(EVENT_MODIFY_STATE, FALSE, buf);
	if (Shutdown == NULL) 
	{
		fprintf(stderr, "Couldn't open event!\n");
		exit(1);
	}

    SetConsoleCtrlHandler(ControlHandler, TRUE);

	while(recv(sock, buf, sizeof(buf), 0) > 0)
	{
		puts("plik!");
	}

	closesocket(sock);
	WSACleanup();
}
