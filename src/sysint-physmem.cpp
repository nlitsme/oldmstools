//========================================================
//
// Physmem
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//
// This program demonstrates how you can open and
// map physical memory. This is essentially the NT 
// equivalent of the \dev\kmem device in UNIX.
//
//========================================================
#include <util/wintypes.h>
#include "debug.h"
//#include <stdio.h>
//#include "native.h"

//========================================================
//
// Native.h
//
// Mark Russinovich
// Systems Internals
// http://www.sysinternals.com
//
// This file contains tyepdefs and defines from NTDDK.H.
// They are included here so that we don't have to
// include NTDDK.H and get all the other stuff that
// we don't really need or want.
//
//========================================================

#define PAGE_NOACCESS          0x01     // winnt
#define PAGE_READONLY          0x02     // winnt
#define PAGE_READWRITE         0x04     // winnt
#define PAGE_WRITECOPY         0x08     // winnt
#define PAGE_EXECUTE           0x10     // winnt
#define PAGE_EXECUTE_READ      0x20     // winnt
#define PAGE_EXECUTE_READWRITE 0x40     // winnt
#define PAGE_EXECUTE_WRITECOPY 0x80     // winnt
#define PAGE_GUARD            0x100     // winnt
#define PAGE_NOCACHE          0x200     // winnt

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS; // windbgkd


typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength / 2), length_is((Length) / 2) ] USHORT * Buffer;
#else // MIDL_PASS
    PWSTR  Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L


typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;


#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }


//
// Functions in NTDLL that we dynamically locate
//

typedef NTSTATUS (__stdcall *PFN_NtUnmapViewOfSection)(
		IN HANDLE  ProcessHandle,
		IN PVOID  BaseAddress
		);

typedef NTSTATUS (__stdcall *PFN_NtOpenSection)(
		OUT PHANDLE  SectionHandle,
		IN ACCESS_MASK  DesiredAccess,
		IN POBJECT_ATTRIBUTES  ObjectAttributes
		);

typedef NTSTATUS (__stdcall *PFN_NtMapViewOfSection)(
		IN HANDLE  SectionHandle,
		IN HANDLE  ProcessHandle,
		IN OUT PVOID  *BaseAddress,
		IN ULONG  ZeroBits,
		IN ULONG  CommitSize,
		IN OUT PLARGE_INTEGER  SectionOffset,	/* optional */
		IN OUT PULONG  ViewSize,
		IN SECTION_INHERIT  InheritDisposition,
		IN ULONG  AllocationType,
		IN ULONG  Protect
		);

typedef VOID (__stdcall *PFN_RtlInitUnicodeString)(
		IN OUT PUNICODE_STRING  DestinationString,
		IN PCWSTR  SourceString
		);

typedef ULONG (__stdcall *PFN_RtlNtStatusToDosError) (
		IN NTSTATUS Status
		);

PFN_NtUnmapViewOfSection NtUnmapViewOfSection;
PFN_NtOpenSection NtOpenSection;
PFN_NtMapViewOfSection NtMapViewOfSection;
PFN_RtlInitUnicodeString RtlInitUnicodeString;
PFN_RtlNtStatusToDosError RtlNtStatusToDosError;

//--------------------------------------------------------
//
// UnmapPhysicalMemory
//
// Maps a view of a section.
//
//--------------------------------------------------------
VOID UnmapPhysicalMemory( DWORD Address )
{
	NTSTATUS		status;

	status = NtUnmapViewOfSection( (HANDLE) -1, (PVOID) Address );
	if( !NT_SUCCESS(status)) {
		error(status, "Unable to unmap view");
	}
}


//--------------------------------------------------------
//
// MapPhysicalMemory
//
// Maps a view of a section.
//
//--------------------------------------------------------
BOOLEAN MapPhysicalMemory( HANDLE PhysicalMemory,
							PDWORD Address, PDWORD Length,
							PDWORD VirtualAddress )
{
	NTSTATUS			ntStatus;
	PHYSICAL_ADDRESS	viewBase;

	*VirtualAddress = 0;
	viewBase.QuadPart = (ULONGLONG) (*Address);
	ntStatus = NtMapViewOfSection (PhysicalMemory,
                               (HANDLE) -1,
                               (PVOID*) VirtualAddress,
                               0L,
                               *Length,
                               &viewBase,
                               Length,
                               ViewShare,
                               0,
                               PAGE_READONLY );

	if( !NT_SUCCESS( ntStatus )) {
		//error( ntStatus, "Could not map view of %X length %X", *Address, *Length );
		return FALSE;					
	}

	*Address = viewBase.LowPart;
	return TRUE;
}


//--------------------------------------------------------
//
// OpensPhysicalMemory
//
// This function opens the physical memory device. It
// uses the native API since 
//
//--------------------------------------------------------
HANDLE OpenPhysicalMemory()
{
	NTSTATUS		status;
	HANDLE			physmem;
	UNICODE_STRING	physmemString;
	OBJECT_ATTRIBUTES attributes;
	WCHAR			physmemName[] = L"\\device\\physicalmemory";

	RtlInitUnicodeString( &physmemString, physmemName );	

	InitializeObjectAttributes( &attributes, &physmemString,
								OBJ_CASE_INSENSITIVE, NULL, NULL );			
	status = NtOpenSection( &physmem, SECTION_MAP_READ, &attributes );

	if( !NT_SUCCESS( status )) {
		error(status, "Could not open \\device\\physicalmemory");
		return NULL;
	}

	return physmem;
}



//--------------------------------------------------------
//
// LocateNtdllEntryPoints
//
// Finds the entry points for all the functions we 
// need within NTDLL.DLL.
//
//--------------------------------------------------------
BOOLEAN LocateNtdllEntryPoints()
{
	if( !(RtlInitUnicodeString = (PFN_RtlInitUnicodeString) GetProcAddress( GetModuleHandle("ntdll.dll"),
			"RtlInitUnicodeString" )) ) {

		return FALSE;
	}
	if( !(NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection) GetProcAddress( GetModuleHandle("ntdll.dll"),
			"NtUnmapViewOfSection" )) ) {

		return FALSE;
	}
	if( !(NtOpenSection = (PFN_NtOpenSection) GetProcAddress( GetModuleHandle("ntdll.dll"),
			"NtOpenSection" )) ) {

		return FALSE;
	}
	if( !(NtMapViewOfSection = (PFN_NtMapViewOfSection) GetProcAddress( GetModuleHandle("ntdll.dll"),
			"NtMapViewOfSection" )) ) {

		return FALSE;
	}
	if( !(RtlNtStatusToDosError = (PFN_RtlNtStatusToDosError) GetProcAddress( GetModuleHandle("ntdll.dll"),
			"RtlNtStatusToDosError" )) ) {

		return FALSE;
	}
	return TRUE;
}

#if 0
//--------------------------------------------------------
//
// Main
// 
// This program drives the command loop
//
//--------------------------------------------------------
int main( int argc, char *argv[] )
{
	HANDLE		physmem;
	DWORD		vaddress, paddress, length;
	char		input[256];
	DWORD		lines;
	char		ch;
	DWORD		i, j;

	printf("\nPhysmem v1.0: physical memory viewer\n"
		   "By Mark Russinovich\n"
		   "Systems Internals - http://www.sysinternals.com\n\n");

	//
	// Load NTDLL entry points
	//
	if( !LocateNtdllEntryPoints() ) {

		printf("Unable to locate NTDLL entry points.\n\n");
		return -1;
	}

	//
	// Open physical memory
	//
	if( !(physmem = OpenPhysicalMemory())) {

		return -1;
	}

	//
	// Enter the command loop
	//
	printf("Enter values in hexadecimal. Enter 'q' to quit.\n");
	while( 1 ) {

		printf("\nAddress: " ); fflush( stdout );
		gets( input );
		if( input[0] == 'q' || input[0] == 'Q' ) break;
		sscanf( input, "%x", &paddress );

		printf("Bytes: "); fflush( stdout );
		gets( input );
		if( input[0] == 'q' || input[0] == 'Q' ) break;
		sscanf( input, "%x", &length );

		//
		// Map it
		//
		if( !MapPhysicalMemory( physmem, &paddress, &length,
								&vaddress )) 
			continue;

		//
		// Dump it
		//
		lines = 0;
		for( i = 0; i < length; i += BYTESPERLINE ) {

			printf("%08X: ", paddress + i );

			for( j = 0; j < BYTESPERLINE; j++ ) {

				if( i+j == length ) break;
				if( j == BYTESPERLINE/2 ) printf("-" );
				printf("%02X ", *(PUCHAR) (vaddress + i +j ));
			}

			for( j = 0; j < BYTESPERLINE; j++ ) {

				if( i+j == length ) break;
				ch = *(PUCHAR) (vaddress + i +j );

				if( __iscsym( ch ) || 
					isalnum( ch ) ||
					ch == ' ') {

					printf("%c", ch);

				} else {

					printf("." );
				}
			}

			printf("\n");

			if( lines++ == LINESPERSCREEN ) {

				printf("-- more -- ('q' to abort)" ); fflush(stdout);
				ch = getchar();
				if( ch == 'q' || ch == 'Q' ) {
					fflush( stdin );
					break;
				}
				lines = 0;
			}
		}

		//
		// Unmap the view
		//
		UnmapPhysicalMemory( vaddress );
	}

	//
	// Close physical memory section
	//
	CloseHandle( physmem );

	return 0;
}
#endif
