/* Service.c */

#include <windows.h>
#include <stdio.h>

extern DWORD InitialiseService(void);
extern void RunService(void);
extern void CleanupService(void);
extern void InterruptService(void);

static DWORD CheckPoint;
static DWORD ServiceState;
static SERVICE_TABLE_ENTRY dispatchTable[2];
static SERVICE_STATUS_HANDLE StatusHandle;

static void UpdateServiceStatus(DWORD State, DWORD Delay, DWORD ErrorCode);

#ifdef _DEBUG

/* Console control handler. This callback is invoke every time a user
 * types CTRL-C or CTRL-BREAK in the console window that the service
 * class in running in.
 * This code is nearly identical to the real service message handle
 * function.
 */

static BOOL WINAPI 
ControlHandler(DWORD dwCtrlType)
{
	switch(dwCtrlType)
	{
	case CTRL_BREAK_EVENT:
	case CTRL_C_EVENT:

		UpdateServiceStatus(SERVICE_STOP_PENDING, 3000, 0);
		InterruptService();

		return TRUE;

	default:
		break;
	}

	UpdateServiceStatus(ServiceState, 0, 0);
	return FALSE;
}

#else

/* The 'real' service message handling function. The address of this
 * function is registered with the service control manager, which invokes
 * this function whenever someone tries to start/stop/pause the service
 * via the control panel or 'net' command.
 */

static void WINAPI 
ServiceMessageHandler(DWORD dwCtrlCode)
{
	switch(dwCtrlCode)
	{
	case SERVICE_CONTROL_STOP:

		UpdateServiceStatus(SERVICE_STOP_PENDING, 3000, 0);
		InterruptService();

		break;

	default:
		break;
	}

	/* We have to update our status before returning. */

	UpdateServiceStatus(ServiceState, 0, 0);
}
#endif


static void
UpdateServiceStatus(DWORD CurrentState, DWORD Delay, DWORD ErrorCode)
{
	SERVICE_STATUS	sshStatus;

	sshStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

	/* List here the operations that can be applied to the service
	 * via the control panel. See the MSDN page for SetServiceStatus for
	 * details.
	 * In this example, a user is allowed to stop/restart the service only.
	 * Consult MSDN help on RegisterServiceCtrlHandler() for reasons why we
	 * don't specify SERVICE_ACCEPT_SHUTDOWN as well.
	 */

	if (CurrentState == SERVICE_START_PENDING)
	{
		sshStatus.dwControlsAccepted = 0;
	}
	else
	{
		sshStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	}

	/* If the error code is any value other than 0 (ERROR_SUCCESS), the
	 * Service Control Manager will bring up an error on the user's screen.
	 */

	sshStatus.dwWin32ExitCode = ErrorCode;
	sshStatus.dwServiceSpecificExitCode = 0;

	sshStatus.dwCurrentState = CurrentState;
	sshStatus.dwWaitHint = Delay;
	sshStatus.dwCheckPoint = ++CheckPoint;

#ifdef _DEBUG
	fprintf(stderr, 
			"%i:\tState now: %x\n\tError if update not sent after %u milliseconds\r\n",
			sshStatus.dwCheckPoint, CurrentState, Delay);

	if (ErrorCode != 0)
	{
		fprintf(stderr, "\tError: %u\r\n", ErrorCode);
	}
	if (CurrentState == SERVICE_STOPPED)
	{
		exit(0);
	}
#else
	SetServiceStatus(StatusHandle, &sshStatus);
#endif

	ServiceState = CurrentState;
}

static VOID WINAPI 
ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	DWORD ErrorValue;

#ifdef _DEBUG
    SetConsoleCtrlHandler(ControlHandler, TRUE);
#else
	StatusHandle = RegisterServiceCtrlHandler(TEXT(""), ServiceMessageHandler);
#endif
			
	/* Tell the Service Control Manager that we are about to start.
	 * We don't specify a watchdog value in this case: if APIPA dies
	 * during initialisation, it displays a modal dialog box on the users
	 * screen (which would cause the watchdog timer to expire, at
	 * which point the SCM would bring up a (redundant) dialog on the
	 * user's screen, alerting them to the failure of the APIPA service.
	 */

	UpdateServiceStatus(SERVICE_START_PENDING, 0, 0);

	/* Do any initialisation code here (optional). */

	ErrorValue = InitialiseService();

	if (ErrorValue != ERROR_SUCCESS)
	{
		/* Initialisation failed: stop the service with an error code. */
		UpdateServiceStatus(SERVICE_STOPPED, 0, ErrorValue);
	}

	/* Tell the SCM that the service is now running. A dwWaitHint of
	 * 0 milliseonds disables the need to continually touch base with the
	 * SCM to let it know that this service is still alive.
	 */

	UpdateServiceStatus(SERVICE_RUNNING, 0, 0);

		
	/* Do main loop here. The service control handler function passed
	 * to RegisterServiceCtrlHandler() at the start of service_main() gets
	 * called whenever the service is to be stopped. Said handler function 
	 * should set a global event/flag to cause this main loop to return.
	 */

	RunService();

	/* Tell the SCM that we are stopping, and that if we haven't notified
	 * it after 3000 milliseconds, that something bad happened during our
	 * shutdown.
	 */

	UpdateServiceStatus(SERVICE_STOP_PENDING, 3000, 0);


	/* Do any shutdown code (eg WSACleanup(), etc) */

	CleanupService();

	/* Tell the SCM that we have stopped. */

	UpdateServiceStatus(SERVICE_STOPPED, 0, 0);

	/* Never get here: the above call to SetServiceStatus() causes 
	 * the call to StartServiceCtrlDispatcher() inside main() to 
	 * return.
	 */
}

void
SetServiceName(const char *ServiceName)
{
	dispatchTable[0].lpServiceName = (char*)ServiceName;
	dispatchTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	dispatchTable[1].lpServiceName = NULL;
	dispatchTable[1].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)NULL;

	CheckPoint = 0;
}

BOOL 
Execute(void)
{
	/* The following call passes control back to the Service Control 
	 * Manager (SCM). The StartServiceCtrlDispatcher() function only 
	 * returns once the service has been stopped, so the code immediately 
	 * following the above snippet should consist only of last minute 
	 * shutdown code.
	 */

#ifdef _DEBUG
	ServiceMain(0, NULL);
#else
	if (!StartServiceCtrlDispatcher(dispatchTable))
	{
		return FALSE;
	}
#endif

	return TRUE;
}

