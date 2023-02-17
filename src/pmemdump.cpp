/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * todo: implement macosx version
 * todo: handle pagefile
 */
#include <util/wintypes.h>
#ifdef _WIN32
#include <io.h>
#endif
#include <fcntl.h>
#ifdef WINCEMEMDMP
#include "itsutils.h"
#include "dllversion.h"
#include <util/rapitypes.h>
#endif
#ifdef WIN32MEMDMP
#include <tlhelp32.h>
#include "sysint-physmem.h"
#endif

#if defined(UNIXMEMDMP)
#include <mach/vm_map.h>
#include <mach/mach_init.h>
#include <mach/mach_error.h>
#include <mach/mach_host.h>
#include "macosx_rights.h"
typedef task_t HANDLE;
#endif

#include "debug.h"
#include "stringutils.h"
#include "ptrutils.h"
#include "args.h"
#include <stdio.h>
#include <string.h>

#include <map>
#include <vector>
#include "util/HiresTimer.h"

// used to pass 64bit arg as 2 dwords for printf %x%08x
#define ARG64F(x)  uint32_t((x)>>32), uint32_t(x)

// done: fix pmemdump -c, such that it does not stop at NUL chars
//      -> stdout set to binmode
// bug: pmemdump -x -f -2 -w 176 0x8e001020 0x12E80
//      after 0x10000 the '-w 176' is broken, should continue.
//
//
DumpUnitType g_dumpunit=DUMPUNIT_BYTE;
DumpFormat g_dumpformat= DUMP_HEX_ASCII;
int g_nMaxUnitsPerLine=-1;
int g_nStepSize= 0;
uint32_t g_blocksize= 0x10000;
bool g_verbose= false;
bool g_fulldump= false;
bool g_showerrors= true;

#ifdef WIN32MEMDMP
// this value is usually stored in the CR3 register
DWORD g_pagedirOffset= 0x39000;
#endif

void CopyProcessMemoryToFile(HANDLE hProc, uint64_t llOffset, uint64_t llLength, char *szOutfile, uint32_t nDataAccess);
void StepProcessMemoryToStdout(HANDLE hProc, uint64_t llOffset, uint64_t llLength, uint32_t nDataAccess);
void DumpProcessMemoryToStdout(HANDLE hProc, uint64_t llOffset, uint64_t llLength, uint32_t nDataAccess);
HANDLE ITGetProcessHandle(const std::string& szProcessName);
#ifdef WINCEMEMDMP
HANDLE GetRapiProcessHandle();
DWORD GetProcessSectionSlot(HANDLE hProc);
#endif

#if defined(UNIXMEMDMP)
HANDLE MachOpenProcessByPid(int pid);
#endif
#ifdef WIN32MEMDMP
DWORD GetActivePagedir();
#endif

void usage()
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    printf("Usage: pmemdump [ -m | -p procname | -h prochandle] start length [ filename ]\n");
    printf("    numbers can be specified as 0x1234abcd\n");
    printf("    -1 -2 -4 : dump as bytes/words/dwords\n");
    printf("    -w NUM : specify nr of words per line\n");
    printf("    -s SIZE: step with SIZE through memory\n");
    printf("    -b SIZE: read in SIZE blocks\n");
    printf("    -a     : ascdump iso hexdump\n");
    printf("    -f     : full - do not summarize identical lines\n");
    printf("    -c     : print raw memory to stdout\n");
    printf("    -x     : print only hex\n");
    printf("    -xx    : print only fixed length ascii dumps\n");
    printf("    -v     : verbose\n");
    printf("    -i     : ignore errors\n");
    printf("\n");
    printf("    -n NAME: view memory in the context of process NAME\n");
#ifdef WIN32MEMDMP
    printf("    -h PID : view memory in the context of process with PID\n");
    printf("    -m     : access virtual kernel memory, via Idle-Pagedir\n");
    printf("    -mm    : access virtual kernel memory, via active-Pagedir\n");
    printf("    -mNUM  : access virtual kernel memory, via specified Pagedir\n");
#else
    printf("    -h NUM : view memory in the context of process with handle NUM\n");
    printf("    -m     : directly access memory - not using ReadProcessMemory\n");
#endif
    printf("    -p     : access physical memory, instead of virtual memory\n");
    printf("        if neither -p, -h or -m is specified, memory is read from the context\n");
    printf("        of rapisrv.exe\n");
    printf("\n");
}
#define PROCID_PHYSMEM 0xFFFFFFFF

int main( int argc, char *argv[])
{
    DebugStdOut();

    uint64_t llOffset=0;
    uint64_t llLength=0;
    uint32_t dwSectionBase= 0;
    char *szOutfile=NULL;
    char *szProcessName= NULL;
    uint32_t dwProcId= PROCID_PHYSMEM;
    bool bDirectMemoryAccess= false;    // false: use readprocessmemory, true: use readmemory
    bool bPhysicalMemoryAccess= false;    // false: use readprocessmemory, true: use readmemory
    bool bIgnoreErrors= false;
    int nDataAccess= 0;
    int nDumpUnitSize= 1;

    int argsfound=0;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 'h': HANDLEULOPTION(dwProcId, uint32_t); break;
            case 'n': HANDLESTROPTION(szProcessName); break;
            case 'i': bIgnoreErrors= true; break;
            case 'm': 
                      bDirectMemoryAccess= true; 
#ifdef WIN32MEMDMP
                      if (argv[i][2]=='m')
                          g_pagedirOffset= GetActivePagedir();
                      else if (argv[i][2] /*|| argc+1>i && argv[i+1][0]!='-'*/)
                          HANDLEULOPTION(g_pagedirOffset, DWORD);
#endif
                      break;
            case 'p': bPhysicalMemoryAccess= true; break;
            case 'v': g_verbose= true; break;
            case 'a': g_dumpformat= DUMP_STRINGS; break;
            case 'c': g_dumpformat= DUMP_RAW; break;
            case 'x': if (argv[i][2]=='x')
                          g_dumpformat= DUMP_ASCII; 
                      else
                          g_dumpformat= DUMP_HEX; 
                      break;
            case 'f': g_fulldump= true; break;
            case 'w': HANDLEULOPTION(g_nMaxUnitsPerLine, int); break;
            case 's': HANDLELLOPTION(g_nStepSize, int); break;
            case 'b': HANDLEULOPTION(g_blocksize, uint32_t); break;

            case '1': case '2': case '4': case '8':
                nDataAccess= argv[i][1]-'0';
                break;
            default:
                usage();
                return 1;
        }
        else switch (argsfound++)
        {
            case 0: llOffset= _strtoi64(argv[i], 0, 0); break;
            case 1: llLength= _strtoi64(argv[i], 0, 0); break;
            case 2: szOutfile= argv[i]; break;
        }
    }

    if (argsfound==0 || argsfound>3)
    {
        usage();
        return 1;
    }
    if (argsfound==1)
        llLength= 0x100;

    if (nDataAccess)
        nDumpUnitSize= nDataAccess;
    if (g_nMaxUnitsPerLine<0) {
        if (g_dumpformat==DUMP_ASCII) 
            g_nMaxUnitsPerLine= 64/nDumpUnitSize;
        else if (g_dumpformat==DUMP_HEX) 
            g_nMaxUnitsPerLine= 32/nDumpUnitSize;
        else
            g_nMaxUnitsPerLine= 16/nDumpUnitSize;
    }

    g_dumpunit= 
        nDumpUnitSize==1?DUMPUNIT_BYTE:
        nDumpUnitSize==2?DUMPUNIT_WORD:
        nDumpUnitSize==4?DUMPUNIT_DWORD:
        nDumpUnitSize==8?DUMPUNIT_QWORD:DUMPUNIT_BYTE;

    if (g_dumpformat==DUMP_RAW) {
#ifdef WIN32
        if (-1==_setmode( _fileno( stdout ), _O_BINARY )) {
            error("_setmode(stdout, rb)");
            return false;
        }
#endif
    }


#ifdef WINCEMEMDMP
    CheckITSDll();
#endif
    HANDLE hProc= INVALID_HANDLE_VALUE;
    if (dwProcId!=PROCID_PHYSMEM)   // -h
    {
        // - do nothing, process handle already there.
#ifdef WIN32MEMDMP
        hProc= OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcId);
#elif defined(WINCEMEMDMP)
        hProc= HANDLE(dwProcId);
#elif defined(UNIXMEMDMP)
        hProc= MachOpenProcessByPid(dwProcId);
#endif
    }
    else if (szProcessName==NULL)           // none of -m, -p, -h, -n
    {
#ifdef WINCEMEMDMP
        hProc= GetRapiProcessHandle();
        if (hProc==INVALID_HANDLE_VALUE) {
            debug("error getting process context\n");
            return 1;
        }
#else
        if (!bPhysicalMemoryAccess) {
            debug("need processname\n");
            return 1;
        }
#endif
    }
    else {                                  // -n
        hProc= ITGetProcessHandle(szProcessName);
        if (hProc==INVALID_HANDLE_VALUE || hProc==0) {
            debug("error getting process context\n");
            return 1;
        }
    }
    if (bDirectMemoryAccess)                // -m
    {
#ifdef WINCEMEMDMP
        if (hProc!=NULL && hProc!=INVALID_HANDLE_VALUE)
            dwSectionBase= GetProcessSectionSlot(hProc);
#endif
        hProc= 0;
    }
    else if (bPhysicalMemoryAccess)         // -p
    {
#ifdef WINCEMEMDMP
        if (hProc!=NULL && hProc!=INVALID_HANDLE_VALUE)
            dwSectionBase= GetProcessSectionSlot(hProc);
#endif
        hProc= INVALID_HANDLE_VALUE;
    }

    if (g_nStepSize)
        StepProcessMemoryToStdout(hProc, llOffset+dwSectionBase, llLength, nDataAccess|(bIgnoreErrors?256:0));
    else if (szOutfile==NULL)
        DumpProcessMemoryToStdout(hProc, llOffset+dwSectionBase, llLength, nDataAccess|(bIgnoreErrors?256:0));
    else
        CopyProcessMemoryToFile(hProc, llOffset+dwSectionBase, llLength, szOutfile, nDataAccess|(bIgnoreErrors?256:0));

#ifdef WINCEMEMDMP
    StopItsutils();
#endif

    return 0;
}

#ifdef WINCEMEMDMP
HANDLE GetRapiProcessHandle()
{
    DWORD outsize=0;
    GetContextResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetContext",
            0, NULL, &outsize, (uint8_t**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITGetContext");
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hProc= outbuf->hProcess;
    RapiFree(outbuf);
    return hProc;
}
HANDLE ITGetProcessHandle(const std::string& szProcessName)
{
    std::Wstring wprocname= ToWString(szProcessName);
    DWORD insize= (wprocname.size()+1)*sizeof(WCHAR);
    WCHAR *inbuf= (WCHAR*)RapiAlloc(insize);

    std::copy(wprocname.begin(), wprocname.end(), inbuf);
    inbuf[wprocname.size()]= 0;

    DWORD outsize=0;
    HANDLE *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetProcessHandle",
            insize, (uint8_t*)inbuf,
            &outsize, (uint8_t**)&outbuf);
    if (res || outbuf==NULL) 
    {
        error(res, "ITGetProcessHandle");
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hproc= *outbuf;

    RapiFree(outbuf);
    RapiFree(inbuf);

    return hproc;
}
typedef std::map<HANDLE,CEPROCESSENTRY> ProcessInfoMap;
bool GetProcessInfo(bool bIncludeHeap, ProcessInfoMap &pinfo)
{
    GetProcessListParams p;
    p.bIncludeHeapUsage= bIncludeHeap;

    DWORD outsize=0;
    GetProcessListResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetProcessList",
            sizeof(GetProcessListParams), (uint8_t*)&p, &outsize, (uint8_t**)&outbuf);

    if (res || outbuf==NULL)
    {
        error(res, "ITGetProcessList");
        return false;
    }
    if (outsize<PTR_DIFF(outbuf, outbuf->pe) 
            || outsize < PTR_DIFF(outbuf, &outbuf->pe[outbuf->nEntries])) {
        debug("INTERNAL ERROR in itsutils.dll: expected %d bytes from ITGetProcessList, got %d\n",
            PTR_DIFF(outbuf, &outbuf->pe[outbuf->nEntries]), outsize);
        return false;
    }

    for (int i=0 ; i<outbuf->nEntries ; i++)
    {
        memcpy(&pinfo[(HANDLE)outbuf->pe[i].dwProcessID], &outbuf->pe[i], sizeof(CEPROCESSENTRY));
    }

    RapiFree(outbuf);
    
    return true;
}

DWORD GetProcessSectionSlot(HANDLE hProc)
{
    ProcessInfoMap pmap;
    if (GetProcessInfo(false, pmap))
        if (pmap.find(hProc)!=pmap.end())
            return pmap[hProc].dwMemoryBase;
    return 0;
}
bool ITReadProcessMemory(HANDLE hProc, uint64_t llOffset, uint8_t *buffer, uint32_t dwBytesWanted, uint32_t *pdwNumberOfBytesRead, uint32_t nDataAccess)
{
    ReadProcessMemoryParams inbuf;
    DWORD outsize=0;
    ReadProcessMemoryResult *outbuf=NULL;

    inbuf.hProcess= hProc;
    inbuf.dwOffset= (DWORD)llOffset;
    inbuf.nSize= dwBytesWanted;
    inbuf.nDataAccess= nDataAccess;
    outbuf= NULL; outsize= 0;
    HRESULT res= ItsutilsInvoke("ITReadProcessMemory",
            sizeof(ReadProcessMemoryParams), (uint8_t*)&inbuf,
            &outsize, (uint8_t**)&outbuf);
    if (res || outbuf==NULL)
    {
        if (g_showerrors)
            error(res, "ITReadProcessMemory");
        return false;
    }
    memcpy(buffer, &outbuf->buffer, outbuf->dwNumberOfBytesRead);
    *pdwNumberOfBytesRead= outbuf->dwNumberOfBytesRead;
    RapiFree(outbuf);

    return true;
}
#elif defined(WIN32MEMDMP)
HANDLE ITGetProcessHandle(const std::string& szProcessName)
{
    HANDLE hTH= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS/*|TH32CS_SNAPNOHEAPS*/, 0);

    PROCESSENTRY32 pe;
    pe.dwSize= sizeof(PROCESSENTRY32);

    HANDLE hProc= INVALID_HANDLE_VALUE;
    if (Process32First(hTH, &pe))
    {
        do {

            if (stricmp(szProcessName.c_str(), pe.szExeFile)==0)
            {
                hProc= OpenProcess(PROCESS_ALL_ACCESS, 0, pe.th32ProcessID);
                if (hProc != INVALID_HANDLE_VALUE && hProc!=NULL)
                    break;
            }
        } while (Process32Next(hTH, &pe));
    }

#ifdef _WIN32_WCE
    CloseToolhelp32Snapshot(hTH);
#else
    CloseHandle(hTH);
#endif

    return hProc;
}

#define MEM_PAGE_SIZE 4096
bool Win32ReadMemory(DWORD dwStart, uint8_t *buf, DWORD dwLength, DWORD *pdwCopied, DWORD nDataAccess)
{
    DWORD nCopied= 0;
    DWORD addr= dwStart;

    if ((nDataAccess&15)==0) {
        while (nCopied < dwLength)
        {
            DWORD nChunkSize= std::min(MEM_PAGE_SIZE-(addr&(MEM_PAGE_SIZE-1)), dwLength-nCopied);

            if (IsBadReadPtr((void*)addr, nChunkSize))
                break;
            memcpy(&buf[nCopied], (void*)addr, nChunkSize);
            nCopied += nChunkSize;
            addr += nChunkSize;
        }
    }
    else if (IsBadReadPtr((void*)addr, dwLength)) {
        // no direct access.
    }
    else if ((nDataAccess&15)==1) {
        while (nCopied < dwLength)
        {
            *(uint8_t*)(buf+nCopied)= *(uint8_t*)addr;
            nCopied++;
            addr++;
        }
    }
    else if (addr&1) {
        // non-word aligned address not allowed
    }
    else if ((nDataAccess&15)==2) {
        while (nCopied+1 < dwLength)
        {
            *(WORD*)(buf+nCopied)= *(WORD*)addr;
            nCopied+=2;
            addr+=2;
        }
    }
    else if (addr&3) {
        // non-dword aligned address not allowed
    }
    else if ((nDataAccess&15)==4) {
        while (nCopied+3 < dwLength)
        {
            *(DWORD*)(buf+nCopied)= *(DWORD*)addr;
            nCopied+=4;
            addr+=4;
        }
    }
    else if ((nDataAccess&15)==8) {
        while (nCopied+7 < dwLength)
        {
            *(uint64_t*)(buf+nCopied)= *(uint64_t*)addr;
            nCopied+=8;
            addr+=8;
        }
    }


    *pdwCopied= nCopied;

    return true;
}

bool Win32ReadPhysicalMemory(DWORD dwStart, uint8_t *buf, DWORD dwLength, uint32_t *pdwCopied, int nDataAccess)
{
    if (!LocateNtdllEntryPoints())
        return false;
    HANDLE physmem = OpenPhysicalMemory();
    if (physmem==NULL || physmem==INVALID_HANDLE_VALUE)
        return false;

    DWORD vaddress;
    DWORD dwRealLength= dwLength;
    DWORD dwRealStart= dwStart;
    if (!MapPhysicalMemory( physmem, &dwRealStart, &dwRealLength, &vaddress ))
        return false;

    *pdwCopied= std::min(dwRealLength-(dwStart-dwRealStart),dwLength);
    DWORD dummy;
    if (!Win32ReadMemory(vaddress+dwStart-dwRealStart, buf, *pdwCopied, &dummy, nDataAccess))
        return false;

    UnmapPhysicalMemory( vaddress );
    CloseHandle( physmem );

    return true;
}

typedef std::vector<DWORD> DwordList;
DwordList pagedir;
std::map<DWORD,DwordList> tablemap;

bool LoadPhysicalPage(DWORD dwAddr, DwordList& pdir)
{
    if (dwAddr&0xfff) {
        debug("ERROR - pagetable at unalign address\n");
        return false;
    }
    pdir.resize(1024);
    uint32_t dwRead=0;
    return Win32ReadPhysicalMemory(dwAddr, (uint8_t*)&pdir[0], pdir.size()*sizeof(DWORD), &dwRead, 0)
        && dwRead==pdir.size()*sizeof(DWORD);
}
bool LoadPageTable(DWORD dwAddr, DwordList& pdir)
{
    return LoadPhysicalPage(dwAddr, pdir);
}
bool LoadPageDirectory(DwordList& pdir)
{
    return LoadPhysicalPage(g_pagedirOffset, pdir);
}

bool MapVirtualToPhysical(DWORD dwVAddr, DWORD *pdwPAddr)
{
    if (pagedir.empty())
        if (!LoadPageDirectory(pagedir))
            return false;

    int pdi= (dwVAddr>>22)&0x3ff;
    DWORD pde= pagedir[pdi];

    // PDE flags:
    // bit0 001 valid
    // bit1 002 
    // bit2 004 
    // bit3 008 
    // bit4 010 
    // bit5 020 
    // bit6 040 
    // bit7 080 smallpage
    // bit8 100 
    // bit9 200 
    // bitA 400 prototype
    // bitB 800 transition
    if ((pde&1)==0)
        return false;

    // T P V
    // 0 0 0 'pagefile' filenr=(pde>>1)&0xf, ofs=(pde&~0xfff)+(vaddr>>12)&0x3ff
    // 0 0 1
    // x 1 0 'prototype', prototypeindex= (pde>>11)
    // x 1 1
    // 1 0 0 'transition'
    // 1 0 1
    bool isSmallPage= (pde&0x80)==0;

    if (isSmallPage)
    {
        DWORD dwPdeAddr= pde&~0xfff;
        if (tablemap[dwPdeAddr].empty())
            if (!LoadPageTable(dwPdeAddr, tablemap[dwPdeAddr]))
                return false;

        int pti= (dwVAddr>>12)&0x3ff;
        DWORD pte= tablemap[dwPdeAddr][pti];
        if ((pte&1)==0)
            return false;

        DWORD dwPteAddr= pte&~0xfff;

        *pdwPAddr= dwPteAddr|(dwVAddr&0xfff);
        return true;
    }
    else {
        DWORD dwPdeAddr= pde&~0x3fffff;
        *pdwPAddr= dwPdeAddr|(dwVAddr&0x3fffff);
        return true;
    }
}

bool Win32ReadVirtualMemory(DWORD dwVAddr, uint8_t *buf, DWORD dwLength, uint32_t *pdwCopied, int nDataAccess)
{
    DWORD dwPAddr;
    if (!MapVirtualToPhysical(dwVAddr, &dwPAddr))
        return false;
    if ((dwPAddr&0xfff)+dwLength > 0x1000) {
        dwLength= 0x1000-(dwPAddr&0xfff);
    }
    return Win32ReadPhysicalMemory(dwPAddr, buf, dwLength, pdwCopied, nDataAccess);
}
bool LoadVirtualData(DWORD dwAddr, DWORD dwSize, DwordList& data)
{
    data.resize(dwSize/sizeof(DWORD));
    uint8_t *ptr= (uint8_t*)&data[0];

    while (dwSize) {
        uint32_t dwRead=0;
        if (!Win32ReadVirtualMemory(dwAddr, ptr, dwSize, &dwRead, 0))
            return false;

        ptr += dwRead;
        dwSize -= dwRead;
    }
    return true;
}
DWORD GetActivePagedir()
{
    DwordList pcr;
    if (!LoadPhysicalPage(0x40000, pcr))
    {
        debug("ERROR loading PCR from physaddr 0x40000\n");
        return false;
    }
    // 0x124 : struct _KTHREAD *CurrentThread;
    DwordList kthread;
    if (!LoadVirtualData(pcr[0x124/4], 0x1b8, kthread))
    {
        debug("ERROR loading KTHREAD from physaddr 0x%08lx\n", pcr[0x124/4]);
        return false;
    }

    // 0x44 : struct _KPROCESS *Process;
    DwordList kprocess;
    if (!LoadVirtualData(kthread[0x44/4], 0x68, kprocess))
    {
        debug("ERROR loading KPROCESS from physaddr 0x%08lx\n", kthread[0x44/4]);
        return false;
    }

    pagedir.clear();
    tablemap.clear();

    return kprocess[0x18/4];    // DirectoryTableBase
}
bool ITReadProcessMemory(HANDLE hProc, uint64_t llOffset, uint8_t *buffer, uint32_t dwBytesWanted, uint32_t *pdwNumberOfBytesRead, uint32_t nDataAccess)
{
    SIZE_T nSize;
    if (hProc==INVALID_HANDLE_VALUE)
        return Win32ReadPhysicalMemory(DWORD(llOffset), buffer, dwBytesWanted, pdwNumberOfBytesRead, nDataAccess);
    else if (hProc==NULL)
        return Win32ReadVirtualMemory(DWORD(llOffset), buffer, dwBytesWanted, pdwNumberOfBytesRead, nDataAccess);
    else if (!ReadProcessMemory(hProc, (LPCVOID)llOffset, buffer, dwBytesWanted, &nSize))
        return false;

    *pdwNumberOfBytesRead= nSize;

    return true;
}
#elif defined(UNIXMEMDMP)
//
// /usr/include/mach/mach_traps.h
// extern kern_return_t task_for_pid( mach_port_name_t target_tport, int pid, mach_port_name_t *t);
//
// /usr/include/mach/mach_init.h
// mach_port_t mach_task_self();
//
// /usr/include/mach/vm_map.h
// extern kern_return_t vm_read( vm_map_t target_task, vm_address_t address, vm_size_t size, vm_offset_t *data, mach_msg_type_number_t *dataCnt);
//


bool MachReadPhysical(uint64_t llOffset, uint8_t *buffer, uint32_t dwBytesWanted, uint32_t *pdwNumberOfBytesRead, uint32_t nDataAccess)
{
    printf("MachReadPhysical not yet implemented\n");
    return false;
}

vm_size_t
child_get_pagesize ()
{
  kern_return_t status;
  static vm_size_t g_cached_child_page_size = vm_size_t(-1);

  if (g_cached_child_page_size == vm_size_t(-1))
    {
      status = host_page_size (mach_host_self (), &g_cached_child_page_size);
      /* This is probably being over-careful, since if we
         can't call host_page_size on ourselves, we probably
         aren't going to get much further.  */
      if (status != KERN_SUCCESS) {
        g_cached_child_page_size = 0;
        printf("ERROR getting pagesize: %d\n", status);
      }
    }

  return g_cached_child_page_size;
}
// http://www.linuxselfhelp.com/gnu/machinfo/html_chapter/mach_5.html
bool MachReadVirtual(HANDLE hProc, uint64_t llOffset, uint8_t *buffer, uint32_t dwBytesWanted, uint32_t *pdwNumberOfBytesRead, uint32_t nDataAccess)
{
// see ~/sources/osx/gdb-1344/src/gdb/gdbserver/macosx-mutils.c
    vm_size_t pagesize= child_get_pagesize();
    vm_size_t page_ofs= llOffset%pagesize;
    vm_address_t startpage= llOffset - page_ofs;

    uint64_t llEnd= llOffset+dwBytesWanted;
    vm_address_t endpage= llEnd;
    if (llEnd%pagesize) {
        endpage += pagesize-(llEnd%pagesize);
    }
    vm_size_t pagebytes= endpage-startpage;
    vm_offset_t ptr;
    mach_msg_type_number_t nread;
    int kret= vm_read(hProc, startpage, pagebytes, &ptr, &nread);
    if (kret != KERN_SUCCESS) {
        //const char*msg= mach_error_string(kret);
        //printf("Unable to read offset %x%08x: %s.", ARG64F(llOffset), msg ? msg : "UNKNOWN");
        return false;
    }
    *pdwNumberOfBytesRead= std::min(nread-page_ofs, vm_size_t(dwBytesWanted));

    memcpy(buffer, (uint8_t*)ptr+page_ofs, *pdwNumberOfBytesRead);

    vm_deallocate(mach_task_self(), ptr, nread);
    return true;
}
HANDLE MachOpenProcessByPid(int pid)
{
    task_t task;
    int kret= task_for_pid(mach_task_self(), pid, &task);
    if (kret != KERN_SUCCESS)
    {
        if (macosx_get_task_for_pid_rights() == 1)
            kret= task_for_pid(mach_task_self(), pid, &task);
    }
    if (kret != KERN_SUCCESS) {
        const char*msg= mach_error_string(kret);
        printf("Unable to locate task for process-id %d: %s.", pid, msg ? msg : "UNKNOWN");
        return -1;
    }
    return task;
}
HANDLE ITGetProcessHandle(const std::string& szProcessName)
{
//  see ~/sources/osx/gdb-1344/src/gdb/macosx/macosx-nat-inferior.c  macosx_process_completer_quoted 


    printf("ITGetProcessHandle not yet implemented\n");
    return false;
}
bool ITReadProcessMemory(HANDLE hProc, uint64_t llOffset, uint8_t *buffer, uint32_t dwBytesWanted, uint32_t *pdwNumberOfBytesRead, uint32_t nDataAccess)
{
    if (hProc==INVALID_HANDLE_VALUE)
        return MachReadPhysical(llOffset, buffer, dwBytesWanted, pdwNumberOfBytesRead, nDataAccess);
    else
        return MachReadVirtual(hProc, llOffset, buffer, dwBytesWanted, pdwNumberOfBytesRead, nDataAccess);
}

#endif

void StepProcessMemoryToStdout(HANDLE hProc, uint64_t llOffset, uint64_t llLength, uint32_t nDataAccess)
{
    ByteVector buffer;
    std::string prevline;
    int nSameCount= 0;

    g_showerrors= false;
    while (llLength)
    {
        buffer.resize(DumpUnitSize(g_dumpunit)*g_nMaxUnitsPerLine);

        uint32_t dwBytesWanted= std::min(llLength, (uint64_t)buffer.size());
        uint32_t dwNumberOfBytesRead;
        std::string line;
        if (!ITReadProcessMemory(hProc, llOffset, &buffer[0], dwBytesWanted, &dwNumberOfBytesRead, nDataAccess)) {
            line= " * * * * * *"; // indicates invalid memory
        }
        else if (dwNumberOfBytesRead) {
            if (g_dumpformat==DUMP_RAW) {
                line.clear();
            }
            else if (g_dumpformat==DUMP_STRINGS)
                line= ascdump(buffer, "\r\n\t", true);
            else if (g_dumpformat==DUMP_ASCII)
                line= asciidump(&buffer[0], dwNumberOfBytesRead);
            else
                line= hexdump(llOffset, &buffer[0], dwNumberOfBytesRead, DumpUnitSize(g_dumpunit), g_nMaxUnitsPerLine).substr(9);
            if (*line.rbegin()=='\n')
                line.resize(line.size()-1);
        }
        else {
            line= " # # # # # #"; // indicates 0 bytes read
        }

        if (g_dumpformat==DUMP_RAW)
            fwrite(&buffer[0], 1, buffer.size(), stdout);
        else if (!g_fulldump && line == prevline) {
            nSameCount++;
        }
        else {
            if (nSameCount==1)
                writedumpline(llOffset-g_nStepSize, prevline);
            else if (nSameCount>1)
                debug("*  [ 0x%x lines ]\n", nSameCount);
            nSameCount= 0;

            writedumpline(llOffset, line);
        }
        prevline= line;
        uint64_t llStep= std::min(llLength, uint64_t(g_nStepSize));
        llLength -= llStep;
        llOffset += llStep;
    }
    if (nSameCount==1)
        writedumpline(llOffset-g_nStepSize, prevline);
    else if (nSameCount>1)
        debug("*  [ 0x%x lines ]\n", nSameCount);
    writedumpline(llOffset, "");
    g_showerrors= true;
}
void DumpProcessMemoryToStdout(HANDLE hProc, uint64_t llOffset, uint64_t llLength, uint32_t nDataAccess)
{
    ByteVector buffer;
    bool bPrevError= false;

    uint32_t flags= hexdumpflags(g_dumpunit, g_nMaxUnitsPerLine, g_dumpformat)
        | (g_fulldump?0:HEXDUMP_SUMMARIZE) | (g_dumpformat==DUMP_RAW?0:HEXDUMP_WITH_OFFSET);

    while (llLength)
    {
        buffer.resize(g_blocksize);
        uint32_t dwWanted= std::min(llLength, (uint64_t)buffer.size());
        uint32_t dwNumberOfBytesRead;
        std::string line;
        if (!ITReadProcessMemory(hProc, llOffset, &buffer[0], dwWanted, &dwNumberOfBytesRead, nDataAccess)) {
            if (!bPrevError)
                debug("%x%08x: * * * * *\n", ARG64F(llOffset));

            dwNumberOfBytesRead= dwWanted;
            bPrevError= true;
        }
        else if (dwNumberOfBytesRead) {
            buffer.resize(dwNumberOfBytesRead);
            bighexdump(llOffset, buffer, flags| (llLength!=dwNumberOfBytesRead ? HEXDUMP_MOREFOLLOWS : 0));

            bPrevError= false;
        }
        else {
            debug("WARNING:  skipping %08lx bytes\n", dwWanted);
            dwNumberOfBytesRead= dwWanted;
        }

        llLength -= dwNumberOfBytesRead;
        llOffset += dwNumberOfBytesRead;
    }
}
std::string hhmmss(uint32_t s)
{
    return stringformat("%2d:%02d:%02d", s/3600, (s/60)%60, s%60);
}
void CopyProcessMemoryToFile(HANDLE hProc, uint64_t llStartOffset, uint64_t llLength, char *szOutfile, uint32_t nDataAccess)
{
    g_showerrors= false;
    debug("CopyProcessMemoryToFile(%08lx, %x%08x, %x%08x, %s)\n",
            hProc, ARG64F(llStartOffset), ARG64F(llLength), szOutfile);
    FILE *f= fopen(szOutfile, "wb");
    if (f==NULL)
    {
        error("Unable to open host/destination file");
        return;
    }

    HiresTimer t_total;
    HiresTimer t_lap;

    ByteVector buffer;
    uint64_t llOffset= llStartOffset;
    while (llLength)
    {
        buffer.resize(g_blocksize);
        uint32_t dwWanted= std::min(llLength, (uint64_t)buffer.size());
        uint32_t dwNumberOfBytesRead;
        if (!ITReadProcessMemory(hProc, llOffset, &buffer[0], dwWanted, &dwNumberOfBytesRead, nDataAccess)) {

            // skip invalid part
            if (-1==fseek(f, dwWanted, SEEK_CUR))
                error("fseek(%08lx)", dwWanted);

            dwNumberOfBytesRead= dwWanted;
        }
        else {
            size_t r= fwrite(&buffer[0], dwNumberOfBytesRead, 1, f);
            if (r!=1)
            {
                error("Error Writing file");
                return;
            }
        }
        llLength -= dwNumberOfBytesRead;
        llOffset += dwNumberOfBytesRead;

        if (g_verbose && t_lap.msecelapsed()>2000) {
            double bps= (double)1000.0*(llOffset-llStartOffset)/t_total.msecelapsed();
            debug("read %x%08x bytes in %6d msec : %8.0f bytes/sec - timeleft: %hs\r", 
                    ARG64F(llOffset-llStartOffset), t_total.msecelapsed(), bps, hhmmss(llLength/bps).c_str());

            t_lap.reset();
        }
    }
    if (g_verbose) {
        debug("read %x%08x bytes in %6d msec : %8.0f bytes/sec\n", 
                ARG64F(llOffset-llStartOffset), t_total.msecelapsed(), (double)1000.0*(llOffset-llStartOffset)/t_total.msecelapsed());
    }

    fclose(f);
    g_showerrors= true;
}

