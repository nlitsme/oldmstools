#ifndef __SYSINT_PHYSMEM_H__
#define __SYSINT_PHYSMEM_H__

VOID UnmapPhysicalMemory( DWORD Address );
BOOLEAN MapPhysicalMemory( HANDLE PhysicalMemory,
							PDWORD Address, PDWORD Length,
							PDWORD VirtualAddress );
HANDLE OpenPhysicalMemory();
BOOLEAN LocateNtdllEntryPoints();

#endif
