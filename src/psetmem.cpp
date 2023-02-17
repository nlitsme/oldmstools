/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 */
// todo: add support to write strings to memory.
//          * -a / -u options
//       add support to load files in memory
//          * -l option
#include <util/wintypes.h>
#ifdef WINCESETMEM
#include "itsutils.h"
#include "dllversion.h"
#include <util/rapitypes.h>
#endif
#ifdef WIN32SETMEM
#include <tlhelp32.h>
#include "sysint-physmem.h"
#endif

#include "stringutils.h"
#include "FileFunctions.h"

#include "debug.h"
#include "args.h"

#include <map>
#include <vector>
#include <string.h>

DWORD g_pagedirOffset= 0x39000;

HANDLE GetRapiProcessHandle();
void MyWriteProcessMemory(HANDLE hProc, DWORD dwOffset, DWORD dwLength, BYTE *pData, DWORD nDataAccess);
HANDLE ITGetProcessHandle(const std::string& szProcessName);
DWORD GetActivePagedir();

void usage()
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    debug("Usage: psetmem [-n procname] [-h prochandle] start data ...\n");
    debug("    numbers can be specified as 0x1234abcd\n");
    debug("    -1 -2 -4 : data are bytes/words/dwords\n");
    debug("    -p  startoffset is a physical memory offset\n");
    debug("    -a  write as ascii string\n");
    debug("    -u  write as unicode string\n");
    debug("    -z SIZE    zero block of memory\n");
    debug("    -l FILENAME [ofs [len]]   load data from file in memory\n");
    debug("    -r N       repeat N times\n");
    debug("    -N  write as NUL terminated string\n");
#ifdef WIN32SETMEM
    printf("    -h PID : view memory in the context of process with PID\n");
    printf("    -m     : access virtual kernel memory, via Idle-Pagedir\n");
    printf("    -mm    : access virtual kernel memory, via active-Pagedir\n");
    printf("    -mNUM  : access virtual kernel memory, via specified Pagedir\n");
#else
    printf("    -h NUM : view memory in the context of process with handle NUM\n");
    printf("    -m     : directly access memory - not using WriteProcessMemory\n");
#endif

}

int main( int argc, char *argv[])
{
    DebugStdOut();

    DWORD dwOffset=0;
    char *szProcessName= NULL;
    HANDLE hProc= INVALID_HANDLE_VALUE;
    bool bDirectMemoryAccess= false;    // false: use readprocessmemory, true: use readmemory
    bool bPhysicalMemoryAccess= false;    // false: use readprocessmemory, true: use readmemory
    bool bWriteAsciiString= false;
    bool bWriteUnicodeString= false;
    bool bNulTerminatedString= true;
    bool bLoadFile= false;
    bool bZeroMemory= false;

    std::vector<DWORD> data;
    StringList strlist;
    int nDataSize= 1;
    DWORD nRepeat= 1;

    int argsfound=0;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 'h': HANDLEULOPTION(hProc, HANDLE); break;
            case 'n': HANDLESTROPTION(szProcessName); break;
            case 'm': bDirectMemoryAccess= true; 
#ifdef WIN32SETMEM
                      if (argv[i][2]=='m')
                          g_pagedirOffset= GetActivePagedir();
                      else if (argv[i][2] /*|| argc+1>i && argv[i+1][0]!='-'*/)
                          HANDLEULOPTION(g_pagedirOffset, DWORD);
#endif
                      break;

            case 'p': bPhysicalMemoryAccess= true; break;
            case 'a': bWriteAsciiString= true; break;
            case 'l': bLoadFile= true; break;
            case 'r': HANDLEULOPTION(nRepeat, DWORD); break;
            case 'z': bZeroMemory= true; break;
            case 'u': bWriteUnicodeString= true; break;
            case 'N': bNulTerminatedString= false; break;

            case '1': case '2': case '4':
                nDataSize= argv[i][1]-'0';
                break;
            default:
                usage();
                return 1;
        }
        else switch (argsfound++)
        {
            case 0: dwOffset= strtoul(argv[i], 0, 0); break;
            default:
                if (bZeroMemory || bLoadFile || bWriteAsciiString || bWriteUnicodeString)
                    strlist.push_back(argv[i]);
                else
                {
                    DWORD arg= strtoul(argv[i], 0, 0);
                    if ( (nDataSize==1 && arg>=0x100)
                            || (nDataSize==2 && arg>=0x10000) )
                    {
                        debug("data larger than specified size: %x >= %x\n", arg, 256<<nDataSize);
                        usage();
                        return 1;
                    }
                    data.push_back(arg);
                }
        }
    }

    if (argsfound==0)
    {
        usage();
        return 1;
    }
    if (nDataSize==0) nDataSize= 1;

    ByteVector buf;
    if (bLoadFile) {
        if (strlist.empty()) {
            usage();
            return 1;
        }
        DWORD dwFileOffset= (strlist.size()>1) ? strtoul(strlist[1].c_str(),0,0) : 0;
        DWORD dwFileLength= (strlist.size()>2) ? strtoul(strlist[2].c_str(),0,0) : 0xFFFFFFFF;
        if (!LoadFileData(strlist[0], buf, dwFileOffset, dwFileLength)) {
            debug("error loading file %s\n", strlist[0].c_str());
            return 1;
        }
        debug("loaded %x bytes\n", buf.size());
    }
    else if (bZeroMemory) {
        if (strlist.size()==0) {
            debug("-z option needs a size parameter\n");
            return 1;
        }
        DWORD dwZeroSize= strtoul(strlist[0].c_str(), 0, 0);
        buf.resize(dwZeroSize);
    }
    else if (bWriteUnicodeString) {
        for (size_t i=0 ; i<strlist.size() ; i++)
            BV_AppendWString(buf, ToWString(strlist[i]));
        if (bNulTerminatedString)
            BV_AppendWord(buf, 0);
    }
    else if (bWriteAsciiString) {
        for (size_t i=0 ; i<strlist.size() ; i++)
            BV_AppendString(buf, strlist[i]);
        if (bNulTerminatedString)
            BV_AppendByte(buf, 0);
    }
    else {
        for (size_t i=0 ; i<data.size() ; i++)
        {
            switch(nDataSize)
            {
                case 1: BV_AppendByte(buf, (BYTE)data[i]); break;
                case 2: BV_AppendWord(buf, (WORD)data[i]); break;
                case 4: BV_AppendDword(buf, data[i]); break;
            }
        }
    }

#ifdef WINCESETMEM
    CheckITSDll();
#endif

    if (bDirectMemoryAccess)
        hProc= NULL;
    else if (bPhysicalMemoryAccess)
        hProc= INVALID_HANDLE_VALUE;
    else if (hProc!=INVALID_HANDLE_VALUE)
    {
        // - do nothing, process handle already there.
#ifdef WIN32SETMEM
        hProc= OpenProcess(PROCESS_ALL_ACCESS, 0, (DWORD)hProc);
#endif
    }
    else if (szProcessName==NULL)
    {
#ifdef WINCESETMEM
        hProc= GetRapiProcessHandle();
        if (hProc==INVALID_HANDLE_VALUE) {
            debug("error getting process context\n");
            return 1;
        }
#else
		debug("need processname\n");
		return 1;
#endif
    }
    else {
        hProc= ITGetProcessHandle(szProcessName);
        if (hProc==INVALID_HANDLE_VALUE) {
            debug("error getting process context\n");
            return 1;
        }
    }

    while (nRepeat) {
        MyWriteProcessMemory(hProc, dwOffset, buf.size(), vectorptr(buf), nDataSize);
        dwOffset += buf.size();
        nRepeat--;
    }

#ifdef WINCESETMEM
    StopItsutils();
#endif

    return 0;
}

#ifdef WINCESETMEM
HANDLE GetRapiProcessHandle()
{
    DWORD outsize=0;
    GetContextResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetContext",
            0, NULL, &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITGetContext");
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hProc= outbuf->hProcess;
    RapiFree(outbuf);
    return hProc;
}
HANDLE ITGetProcessHandle(const std::string& processName)
{
    std::Wstring wprocname= ToWString(processName);
    DWORD insize= (wprocname.size()+1)*sizeof(WCHAR);
    WCHAR *inbuf= (WCHAR*)RapiAlloc(insize);

    std::copy(wprocname.begin(), wprocname.end(), inbuf);
    inbuf[wprocname.size()]= 0;

    DWORD outsize=0;
    HANDLE *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetProcessHandle",
            insize, (BYTE*)inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL) {
        error(res, "ITGetProcessHandle");
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hproc= *outbuf;

    RapiFree(outbuf);

    return hproc;
}

bool ITWriteProcessMemory(HANDLE hProc, DWORD dwOffset, BYTE *buffer, DWORD dwBufLength, SIZE_T *pdwNumberOfBytesWritten, DWORD nDataAccess)
{
    WriteProcessMemoryParams *inbuf;
    DWORD outsize=0;
    WriteProcessMemoryResult *outbuf=NULL;

    debug("ITWriteProcessMemory(%08lx, %08lx, %08lx, %d)\n", hProc, dwOffset, dwBufLength, nDataAccess);
    DWORD insize= sizeof(WriteProcessMemoryParams)+dwBufLength;
    inbuf= (WriteProcessMemoryParams *)RapiAlloc(insize);

    inbuf->hProcess= hProc;
    inbuf->dwOffset= dwOffset;
    inbuf->nSize= dwBufLength;
    inbuf->nDataAccess= nDataAccess;
    memcpy(inbuf->buffer, buffer, dwBufLength);

    outbuf= NULL; outsize= 0;
    HRESULT res= ItsutilsInvoke("ITWriteProcessMemory",
            insize, (BYTE*)inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITWriteProcessMemory(%08lx, %08lx, %08lx)", hProc, dwOffset, dwBufLength);
        return false;
    }
    *pdwNumberOfBytesWritten= outbuf->dwNumberOfBytesWritten;
    RapiFree(outbuf);

    return true;
}
#else
HANDLE GetRapiProcessHandle()
{
    return GetCurrentProcess();
}
HANDLE ITGetProcessHandle(const std::string& szProcessName)
{
    HANDLE hTH= CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS/*|TH32CS_SNAPNOHEAPS*/, 0);

    PROCESSENTRY32 pe;
    pe.dwSize= sizeof(PROCESSENTRY32);

    HANDLE hProc= INVALID_HANDLE_VALUE;
    if (Process32First(hTH, &pe))
    {
        do {

            if (stringicompare(szProcessName, std::string(pe.szExeFile))==0)
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

bool WriteMemory(DWORD dwStart, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, DWORD nDataAccess)
{
    DWORD nCopied= 0;
    DWORD addr= dwStart;

    if (nDataAccess==0) {
        while (nCopied < dwLength)
        {
            DWORD nChunkSize= std::min(MEM_PAGE_SIZE-(addr&(MEM_PAGE_SIZE-1)), dwLength-nCopied);

            if (IsBadWritePtr((void*)addr, nChunkSize))
                break;
            memcpy((void*)addr, &buf[nCopied], nChunkSize);
            nCopied += nChunkSize;
            addr += nChunkSize;
        }
    }
    else if (IsBadWritePtr((void*)addr, dwLength)) {
        // no direct access.
    }
    else if (nDataAccess==1) {
        while (nCopied < dwLength)
        {
            *(BYTE*)addr= *(BYTE*)(buf+nCopied);
            nCopied++;
            addr++;
        }
    }
    else if (addr&1) {
        // non-word aligned address not allowed
    }
    else if (nDataAccess==2) {
        while (nCopied+1 < dwLength)
        {
            *(WORD*)addr=*(WORD*)(buf+nCopied);
            nCopied+=2;
            addr+=2;
        }
    }
    else if (addr&3) {
        // non-dword aligned address not allowed
    }
    else if (nDataAccess==4) {
        while (nCopied+3 < dwLength)
        {
            *(DWORD*)addr=*(DWORD*)(buf+nCopied);
            nCopied+=4;
            addr+=4;
        }
    }

    *pdwCopied= nCopied;

    return true;
}

bool WritePhysicalMemory(DWORD dwStart, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, int nDataAccess)
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
	SIZE_T dummy;
    if (!WriteMemory(vaddress+dwStart-dwRealStart, buf, *pdwCopied, &dummy, nDataAccess))
        return false;

    UnmapPhysicalMemory( vaddress );
    CloseHandle( physmem );

    return true;
}
bool ReadMemory(DWORD dwStart, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, DWORD nDataAccess)
{
    DWORD nCopied= 0;
    DWORD addr= dwStart;

    if (nDataAccess==0) {
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
    else if (nDataAccess==1) {
        while (nCopied < dwLength)
        {
            *(BYTE*)(buf+nCopied)= *(BYTE*)addr;
            nCopied++;
            addr++;
        }
    }
    else if (addr&1) {
        // non-word aligned address not allowed
    }
    else if (nDataAccess==2) {
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
    else if (nDataAccess==4) {
        while (nCopied+3 < dwLength)
        {
            *(DWORD*)(buf+nCopied)= *(DWORD*)addr;
            nCopied+=4;
            addr+=4;
        }
    }

    *pdwCopied= nCopied;

    return true;
}

bool ReadPhysicalMemory(DWORD dwStart, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, int nDataAccess)
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
	SIZE_T dummy;
    if (!ReadMemory(vaddress+dwStart-dwRealStart, buf, *pdwCopied, &dummy, nDataAccess))
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
    SIZE_T dwRead=0;
    return ReadPhysicalMemory(dwAddr, (BYTE*)vectorptr(pdir), pdir.size()*sizeof(DWORD), &dwRead, 0)
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

    if ((pde&1)==0)
        return false;

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

bool ReadVirtualMemory(DWORD dwVAddr, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, int nDataAccess)
{
    DWORD dwPAddr;
    if (!MapVirtualToPhysical(dwVAddr, &dwPAddr))
        return false;
    if ((dwPAddr&0xfff)+dwLength > 0x1000) {
        dwLength= 0x1000-(dwPAddr&0xfff);
    }
    return ReadPhysicalMemory(dwPAddr, buf, dwLength, pdwCopied, nDataAccess);
}
bool WriteVirtualMemory(DWORD dwVAddr, BYTE *buf, DWORD dwLength, SIZE_T *pdwCopied, int nDataAccess)
{
    DWORD dwPAddr;
    if (!MapVirtualToPhysical(dwVAddr, &dwPAddr))
        return false;
    if ((dwPAddr&0xfff)+dwLength > 0x1000) {
        dwLength= 0x1000-(dwPAddr&0xfff);
    }
    return WritePhysicalMemory(dwPAddr, buf, dwLength, pdwCopied, nDataAccess);
}

bool LoadVirtualData(DWORD dwAddr, DWORD dwSize, DwordList& data)
{
    data.resize(dwSize/sizeof(DWORD));
    BYTE *ptr= (BYTE*)vectorptr(data);

    while (dwSize) {
        SIZE_T dwRead=0;
        if (!ReadVirtualMemory(dwAddr, ptr, dwSize, &dwRead, 0))
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
bool ITWriteProcessMemory(HANDLE hProc, DWORD dwOffset, BYTE *buffer, DWORD dwBufLength, SIZE_T *pdwNumberOfBytesWritten, DWORD nDataAccess)
{
    if (hProc==INVALID_HANDLE_VALUE)
        return WritePhysicalMemory(dwOffset, buffer, dwBufLength, pdwNumberOfBytesWritten, nDataAccess);
    else if (hProc==NULL)
        return WriteVirtualMemory(dwOffset, buffer, dwBufLength, pdwNumberOfBytesWritten, nDataAccess);
    else if (!WriteProcessMemory(hProc, (LPVOID)dwOffset, buffer, dwBufLength, pdwNumberOfBytesWritten))
        return false;

    return true;
}
#endif


void MyWriteProcessMemory(HANDLE hProc, DWORD dwOffset, DWORD dwLength, BYTE *pData, DWORD nDataAccess)
{
    debug("writemem(%08lx, %08lx, %08lx, %d)\n", hProc, dwOffset, dwLength, nDataAccess);
    while (dwLength)
    {
        SIZE_T dwNumberOfBytesWritten;
        if (!ITWriteProcessMemory(hProc, dwOffset, pData, std::min(dwLength, (DWORD)32768), &dwNumberOfBytesWritten, nDataAccess))
            return;

        if (dwNumberOfBytesWritten==0 || dwNumberOfBytesWritten>dwLength)
            return;
        dwLength -= dwNumberOfBytesWritten;
        dwOffset += dwNumberOfBytesWritten;
        pData += dwNumberOfBytesWritten;
    }
}

