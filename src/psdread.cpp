/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * this file implements reading from and writing to,
 * sdcards in local ( usb or pccard ) or remote ( in pda )
 *
 * todo: add 'format disk' option
 *   see http://blog.opennetcf.org/afeinman/PermaLink,guid,0395ab14-76ef-4961-8496-05e273de1bf4.aspx
 *
 * todo: add '-b' switch, to specify sectorsize
 *
 */

#include <util/wintypes.h>
#ifndef _NO_RAPI
#include "itsutils.h"
#endif
#include "debug.h"
#include "args.h"
#include <stdio.h>
#include "stringutils.h"
#include "vectorutils.h"
#ifndef _NO_RAPI
#include "dllversion.h"
#include <util/rapitypes.h>
#endif

#define ACT_ON_DISKVOLUME 0x80000000

bool g_ignoreerror= false;
bool g_bVerbose= false;
bool g_bWriteNonRemovable= false;

int g_chunksize=32768;
int g_sectorsize=-1;

bool FindCardSize(bool bLocal, DWORD dwDiskNr);
bool ReadSDCard(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, BYTE *buffer, DWORD dwBytesWanted, DWORD *pdwNumberOfBytesRead);
bool CopySDCardToFile(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength, const std::string& outfilename);
bool HexdumpSDCardToStdout(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength);
bool CopyFileToSDCard(const std::string& infilename, DWORD dwFileOffset, bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength);
bool GetDeviceInfoForDrive(char drvchar, DWORD& dwDiskNr, bool& bRemovable);
bool GetDeviceInfoForPhysDrive(DWORD dwDiskNr, bool& bRemovable);
#ifndef _NO_RAPI
bool ITSDCardInfo(DWORD dwDiskNr, DWORD& totalsectors, DWORD& sectorsize, ByteVector &cardid);
#endif
std::string sizestring(double size);
std::string longhexnumber(DWORD dwHigh, DWORD dwLow);
DWORD GetFileSize(const std::string& filename);
void Add32To64(DWORD& dwHigh, DWORD& dwLow, DWORD dwOffset);
void ListDevices();

void usage(const std::string& cmd)
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    if (cmd.substr(0,7)=="psdread" || cmd.substr(0,6)=="sdread") {
        printf("Usage: %ssdread %s start [ length [ filename ] ]\n", cmd[0]=='p'?"p":"",
                cmd[0]=='p'?"[-DSKNR | drive: | -pDISKNR ]":"[ drive: | -pDISKNR ]");
        printf("    -t     : find exact disk size\n");
        printf("    -l     : list all diskdevices\n");
        printf("    -p   drive: specifies volume/partition instead of physicaldisk\n");
#ifndef _NO_RAPI
        printf("    -3   is the disknr of the sdcard on the xda2/himalaya\n");
        printf("    -1   is the disknr of the sdcard on the xda1/wallaby\n");
#else
        printf("    -p0  reads \\\\.\\PhysicalDrive0\n");
#endif
//        printf("    -us    : offsets and lengths are specified in sector units\n");
//        printf("    -u N   : offsets and lengths are specified in size N units\n");
        printf("    -b SECTORSIZE\n");
        printf("    -B CHUNKSIZE\n");
        printf("if the filename is omitted, the data is hexdumped to stdout\n");
        printf("if no length is specified, 512 bytes are printed\n");
        printf("\n");
        printf("note that the cardsize reported by the OS is incorrect under winxp\n");
        printf("numbers can be specified as hex (ex: 0x8000)  or decimal (ex: 32768)\n");

    }
    else if (cmd.substr(0,8)=="psdwrite" || cmd.substr(0,7)=="sdwrite") {
        printf("Usage: %ssdwrite %s [-s fileseek] filename [ cardseek [ length ] ]\n", cmd[0]=='p'?"p":"", 
                cmd[0]=='p'?"[-DSKNR | drive:]":"drive:");
#ifndef _NO_RAPI
        printf("    -3   is the disknr of the sdcard on the xda2/himalaya\n");
        printf("    -1   is the disknr of the sdcard on the xda1/wallaby\n");
#endif
        printf("    -f   enable writing nonremovable disks\n");
        printf("    -format   format disk\n");
        printf("    -p   drive: specifies volume/partition instead of physicaldisk\n");
        printf("%ssdwrite will only write to removable devices.\n", cmd[0]=='p'?"p":"");
        printf("when no length is specified, the whole file is written\n");
        printf("when no cardseek offset is specified, data is written to the start of the card\n");
        printf("\n");
        printf("numbers can be specified as hex (ex: 0x8000)  or decimal (ex: 32768)\n");

    }
    else {
        printf("ERROR: don't know what I am - %hs\n", cmd.c_str());
    }
}
std::string GetFileFromPath(const std::string& name)
{
    size_t lastslash= name.find_last_of("\\/");
    if (lastslash==name.npos)
        return name;

    return name.substr(lastslash+1);
}
int main( int argc, char *argv[])
{
    DebugStdOut();

    std::string cmd= tolower(GetFileFromPath(argv[0]));
    bool bWriting= false;
    if (cmd.substr(0,7)=="psdread" || cmd.substr(0,6)=="sdread") {
        bWriting= false;
    }
    else if (cmd.substr(0,8)=="psdwrite" || cmd.substr(0,7)=="sdwrite") {
        bWriting= true;
    }
    else {
        printf("ERROR: don't know what I am : %hs\n", cmd.c_str());
        return 1;
    }

    DWORD dwCardOffsetL=0;
    DWORD dwCardOffsetH=0;
    DWORD dwLength=0;
    std::string filename;
    bool doFindSize= false;
    bool doListDevices= false;

    DWORD dwDiskNr=0xffff;
    bool bLocal= true;
    bool bRemovable= false;
    bool bActOnDiskVolume= false;
    bool bFormatDisk= false;

    DWORD dwFileOffset= 0;

    StringList args;

    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 't': doFindSize= true; break;
            case 'l': doListDevices= true; break;
            case 'b': HANDLEULOPTION(g_sectorsize, int); break;
            case 'B': HANDLEULOPTION(g_chunksize, int); break;
            case 'v': g_bVerbose= true; break;
            case 'f': if (std::string(argv[i]+1)=="format")
                          bFormatDisk= true;
                      else
                          g_bWriteNonRemovable= true;
                      break;
/*
            case 'u': if (argv[i][2]=='s')
                          g_dwUnitSize= 0x200; 
                      else 
                          HANDLEULOPTION(g_dwUnitSize, DWORD);
                      break;
*/
            case 's': HANDLEULOPTION(dwFileOffset, DWORD); break;
            case 'p': if (argv[i][2])
                          dwDiskNr= strtol(argv[i]+2, 0, 0);
                      else
                          bActOnDiskVolume= true;
                      break;
            default:
                if (isdigit(argv[i][1])) {
                    dwDiskNr= strtol(argv[i]+1, 0, 0);
                    bLocal= false;
                    break;
                }
                usage(cmd);
                return 1;
        }
        else 
            args.push_back(argv[i]);
    }

    int res= 0;

    StringList::iterator ai= args.begin();
    if (doListDevices) {
        if (ai!=args.end()) { usage(cmd); return 1; }
        ListDevices();
        return 0;
    }
    if (bLocal) {
        if (ai==args.end() && dwDiskNr==0xffff) { usage(cmd); return 1; }
        if (dwDiskNr==0xffff) {
            std::string drvname= *ai++;
            if (drvname.length()!=2 || drvname[1]!=':') {
                printf("invalid drivename specified - should be letteer + ':'\n");
                return 1;
            }
            if (!GetDeviceInfoForDrive(drvname[0], dwDiskNr, bRemovable))
                return 1;
            if (bActOnDiskVolume)
                dwDiskNr= (drvname[0]-'@')|ACT_ON_DISKVOLUME;
        }
        else {
            if (!GetDeviceInfoForPhysDrive(dwDiskNr, bRemovable))
                return 1;
        }
        if (g_sectorsize==-1)
            g_sectorsize= 512;
    }
    else {
#ifndef _NO_RAPI
        CheckITSDll();
        DWORD totalsectors;
        DWORD sectorsize;
        ByteVector cardid;
        if (bActOnDiskVolume)
            dwDiskNr |= ACT_ON_DISKVOLUME;
        if (ITSDCardInfo(dwDiskNr, totalsectors, sectorsize, cardid))
        {
            printf("remote disk %d has %d sectors of %d bytes - %hsbyte\n", 
                dwDiskNr,
                totalsectors, sectorsize, sizestring(totalsectors*sectorsize).c_str());
            if (cardid.size())
                printf("SerialNr: %hs\n", hexdump(cardid).c_str());
        }
        if (g_sectorsize==-1)
            g_sectorsize= sectorsize;
// !! not actually so, but I don't know how to tell the difference between internal and external 
// storage on WinCE yet.
        bRemovable= true;
#else
        printf("No RAPI version\n");
        exit(1);
#endif
    }
    if (doFindSize) {
        if (ai!=args.end()) { usage(cmd); return 1; }
        if (!FindCardSize(bLocal, dwDiskNr))
            return 1;
        return 0;
    }
    if (ai==args.end()) { usage(cmd); return 1; }

    if (bWriting) {
        if (!bRemovable && !g_bWriteNonRemovable) {
            printf("ERROR: this is not a removable disk - will not write\n");
            return 1;
        }
        if (ai==args.end()) { usage(cmd); return 1; }
        filename= *ai++;
        if (ai!=args.end()) {
            int64_t ui64= _strtoi64((*ai++).c_str(), 0, 0);

            dwCardOffsetH= (DWORD)(ui64>>32);
            dwCardOffsetL= (DWORD)ui64;
        }
        else {
            dwCardOffsetH= dwCardOffsetL= 0;
        }
        if (ai!=args.end())
            dwLength= strtoul((*ai++).c_str(), 0, 0);
        else
            dwLength= GetFileSize(filename)-dwFileOffset;
        if (ai!=args.end()) { usage(cmd); return 1; }

        if (!CopyFileToSDCard(filename, dwFileOffset, bLocal, dwDiskNr, dwCardOffsetH, dwCardOffsetL, dwLength))
            res= 1;
    }
    else {
        if (!bRemovable)
            printf("WARNING: this is not a removable disk\n");

        int64_t ui64= _strtoi64((*ai++).c_str(), 0, 0);

        dwCardOffsetH= (DWORD)(ui64>>32);
        dwCardOffsetL= (DWORD)ui64;

        dwLength= 0x200;
        if (ai!=args.end()) dwLength= strtoul((*ai++).c_str(), 0, 0);
        if (ai!=args.end()) filename= *ai++;

        if (ai!=args.end()) { usage(cmd); return 1; }
        if (filename.empty()) {
            if (!HexdumpSDCardToStdout(bLocal, dwDiskNr, dwCardOffsetH, dwCardOffsetL, dwLength))
                res= 1;
        }
        else  {
            if (!CopySDCardToFile(bLocal, dwDiskNr, dwCardOffsetH, dwCardOffsetL, dwLength, filename))
                res= 1;
        }
    }

#ifndef _NO_RAPI
    if (!bLocal)
        StopItsutils();
#endif
    return res;
}

void ListDevices()
{
    g_ignoreerror= true;
// todo: merge driveletter + physdisk lists
    for (char drv='A' ; drv<='Z' ; drv++)
    {
        DWORD dwDiskNr;
        bool bRemovable;
        if (GetDeviceInfoForDrive(drv, dwDiskNr, bRemovable))
            printf("      disknr=%d   %s disk\n", dwDiskNr, bRemovable?"removable":"fixed");
    }
    for (int disk=0 ; disk<16 ; disk++)
    {
        bool bRemovable;
        if (GetDeviceInfoForPhysDrive(disk, bRemovable))
            printf("      disknr=%d   %s disk\n", disk, bRemovable?"removable":"fixed");
    }

#ifndef _NO_RAPI
    CheckITSDll();
    for (int disknr= 0 ; disknr<16 ; disknr++)
    {
        DWORD totalsectors;
        DWORD sectorsize;
        ByteVector cardid;
        if (ITSDCardInfo(disknr, totalsectors, sectorsize, cardid))
        {
            printf("remote disk %d has %d sectors of %d bytes - %hsbyte\n", 
                disknr,
                totalsectors, sectorsize, sizestring(totalsectors*sectorsize).c_str());
            if (cardid.size())
                printf("SerialNr: %hs\n", hexdump(cardid).c_str());
        }
    }
#endif
    g_ignoreerror= false;

}
// ........................................
// writing

#ifndef _NO_RAPI
bool ITWriteSDCard(DWORD dwDiskNr, DWORD dwDiskOffset, const BYTE *buffer, DWORD dwBufferSize, DWORD *pdwNumberOfBytesWritten)
{
    int insize= sizeof(WriteSDCardParams)+dwBufferSize;
    WriteSDCardParams *inbuf= (WriteSDCardParams *)RapiAlloc(insize);
    DWORD outsize=0;
    WriteSDCardResult *outbuf=NULL;
    inbuf->dwDiskNr= dwDiskNr;
    inbuf->dwOffset= dwDiskOffset;
    inbuf->dwSize= dwBufferSize;
    memcpy(inbuf->buffer, buffer, dwBufferSize);

    HRESULT res= ItsutilsInvoke("ITWriteSDCard",
            insize, (BYTE*)inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITWriteSDCard");
        return false;
    }
    *pdwNumberOfBytesWritten= outbuf->dwNumberOfBytesWritten;
    RapiFree(outbuf);
    return true;
}
#endif
bool LocalWriteSDCard(DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, const BYTE *buffer, DWORD dwBufferSize, DWORD *pdwNumberOfBytesWritten)
{
    std::string diskname= (dwDiskNr&ACT_ON_DISKVOLUME)
        ? stringformat("\\\\.\\%c:", (dwDiskNr&0x1f)+'@')
        : stringformat("\\\\.\\PhysicalDrive%d", (dwDiskNr&0x7fff));

    HANDLE h= CreateFile(diskname.c_str(), GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (h==INVALID_HANDLE_VALUE)
	{
		error("opening device %s for reading", diskname.c_str());
        return false;
	}
    LONG high= dwOffsetH;
    if (INVALID_SET_FILE_POINTER==SetFilePointer(h, dwOffsetL, &high, FILE_BEGIN))
    {
		error("seeking to %hs", longhexnumber(dwOffsetH, dwOffsetL).c_str());
        return false;
    }

    if (!WriteFile(h, buffer, dwBufferSize, pdwNumberOfBytesWritten, NULL))
	{
        if (!g_ignoreerror)
            error("writing 0x%x bytes to %hs", dwBufferSize, longhexnumber(dwOffsetH, dwOffsetL).c_str());
		return false;
	} 

    return true;
}
bool WriteSDCard(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, const BYTE *buffer, DWORD dwBufferSize, DWORD *pdwNumberOfBytesWritten)
{
    if (g_bVerbose)
        printf("writing 0x%x bytes to %hs\n", dwBufferSize, longhexnumber(dwOffsetH, dwOffsetL).c_str());
    if (bLocal)
        return LocalWriteSDCard(dwDiskNr, dwOffsetH, dwOffsetL, buffer, dwBufferSize, pdwNumberOfBytesWritten);
#ifndef _NO_RAPI
    else if (dwOffsetH==0)
        return ITWriteSDCard(dwDiskNr, dwOffsetL, buffer, dwBufferSize, pdwNumberOfBytesWritten);
    else {
        printf("WARNING: >4G disks not yet supported for remote sd card\n");
        return false;
    }
#else
    else {
        printf("WARNING: RAPI disabled\n");
        return false;
    }
#endif
}


bool CopyFileToSDCard(const std::string& infilename, DWORD dwFileOffset, bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength)
{
    debug("CopyFileToSDCard(%s:%08lx, %d, %hs, %08lx)\n",
            infilename.c_str(), dwFileOffset, dwDiskNr, longhexnumber(dwOffsetH, dwOffsetL).c_str(), dwLength);
    HANDLE hSrc = CreateFile(infilename.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hSrc)
    {
        error("Unable to open host/destination file");
        return false;
    }

    if (INVALID_SET_FILE_POINTER==SetFilePointer(hSrc, dwFileOffset, NULL, FILE_BEGIN))
    {
        error("Unable to seek to data start");
        return false;
    }

    while (dwLength)
    {
        ByteVector buffer(g_chunksize);
        DWORD dwBufferOffset= 0;

        // if start offset not at sector boundary, first read until sector boundary.
        DWORD dwWanted= std::min(dwLength, (dwOffsetL&(g_sectorsize-1)) ? g_sectorsize-(dwOffsetL&(g_sectorsize-1)): (DWORD)buffer.size());

        // if end offset not at sector boundary, first read complete sectors.
        if ((dwWanted&(g_sectorsize-1))!=0 && dwWanted>g_sectorsize)
            dwWanted &= ~(g_sectorsize-1);

        // if not at sector boundary, or less than one sector to read, first fill buffer
        if (dwOffsetL&(g_sectorsize-1) || dwLength<g_sectorsize) {
            DWORD nRead;
            if (!ReadSDCard(bLocal, dwDiskNr, dwOffsetH, dwOffsetL&~(g_sectorsize-1), &buffer[0], g_sectorsize, &nRead))
                return false;
            dwBufferOffset= dwOffsetL&(g_sectorsize-1);
        }

        DWORD dwNumRead;
        if (!ReadFile(hSrc, &buffer[dwBufferOffset], dwWanted, &dwNumRead, NULL))
        {
            error("Error Reading file");
            return false;
        }
        //printf("wanted=%08lx  bufofs=%08lx  ofs=%08lx read=%08lx\n", dwWanted, dwBufferOffset, dwOffsetL, dwNumRead);

        DWORD dwToWrite= dwNumRead;
        if (dwOffsetL&(g_sectorsize-1) || dwLength<g_sectorsize) {
            dwToWrite= g_sectorsize;
        }
        DWORD dwNumberOfBytesWritten;
        if (!WriteSDCard(bLocal, dwDiskNr, dwOffsetH, dwOffsetL&~(g_sectorsize-1), &buffer[0], dwToWrite, &dwNumberOfBytesWritten))
            return false;

        dwLength -= dwNumRead;
        Add32To64(dwOffsetH, dwOffsetL, dwNumRead);
    }

    CloseHandle (hSrc);

    return true;
}

#ifndef _NO_RAPI
// ........................................
// reading
bool ITReadSDCard(DWORD dwDiskNr, DWORD dwOffset, BYTE *buffer, DWORD dwBytesWanted, DWORD *pdwNumberOfBytesRead)
{
    ReadSDCardParams inbuf;
    DWORD outsize=0;
    ReadSDCardResult *outbuf=NULL;

    inbuf.dwDiskNr= dwDiskNr;
    inbuf.dwOffset= dwOffset;
    inbuf.dwSize= dwBytesWanted;
    outbuf= NULL; outsize= 0;
    HRESULT res= ItsutilsInvoke("ITReadSDCard",
            sizeof(ReadSDCardParams), (BYTE*)&inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        if (!g_ignoreerror)
            error(res, "ITReadSDCard");
        return false;
    }
    memcpy(buffer, &outbuf->buffer, outbuf->dwNumberOfBytesRead);
    *pdwNumberOfBytesRead= outbuf->dwNumberOfBytesRead;
    RapiFree(outbuf);
    return true;
}
#endif

#ifndef _NO_RAPI
bool ITSDCardInfo(DWORD dwDiskNr, DWORD& totalsectors, DWORD& sectorsize, ByteVector &cardid)
{
    SDCardInfoParams inbuf;
    DWORD outsize=0;
    SDCardInfoResult *outbuf=NULL;

    inbuf.dwDiskNr= dwDiskNr;
    outbuf= NULL; outsize= 0;
    HRESULT res= ItsutilsInvoke("ITSDCardInfo",
            sizeof(SDCardInfoParams), (BYTE*)&inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        if (!g_ignoreerror)
            error(res, "ITSDCardInfo");
        return false;
    }
    totalsectors= outbuf->totalBlocks;
    sectorsize= outbuf->blockSize;

    if (outbuf->cardidLength) {
        cardid.resize(outbuf->cardidLength);
        memcpy(vectorptr(cardid), outbuf->cardid, outbuf->cardidLength);
    }
    else {
        cardid.clear();
    }

    RapiFree(outbuf);
    return true;
}
#endif

bool LocalReadSDCard(DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, BYTE *buffer, DWORD dwBytesWanted, DWORD *pdwNumberOfBytesRead)
{
    std::string diskname= (dwDiskNr&ACT_ON_DISKVOLUME)
        ? stringformat("\\\\.\\%c:", (dwDiskNr&0x1f)+'@')
        : stringformat("\\\\.\\PhysicalDrive%d", (dwDiskNr&0x7fff));

    HANDLE h= CreateFile(diskname.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (h==INVALID_HANDLE_VALUE)
	{
		error("opening device %s for reading", diskname.c_str());
        return false;
	}
    LONG high= dwOffsetH;
    if (INVALID_SET_FILE_POINTER==SetFilePointer(h, dwOffsetL, &high, FILE_BEGIN))
    {
		error("seeking to %hs", longhexnumber(dwOffsetH, dwOffsetL).c_str());
        return false;
    }

    if (!ReadFile(h, buffer, dwBytesWanted, pdwNumberOfBytesRead, NULL))
	{
        if (!g_ignoreerror)
            error("reading 0x%x bytes from %hs", dwBytesWanted, longhexnumber(dwOffsetH, dwOffsetL).c_str());
		return false;
	} 

    return true;
}
bool ReadSDCard(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, BYTE *buffer, DWORD dwBytesWanted, DWORD *pdwNumberOfBytesRead)
{
    if (g_bVerbose)
        printf("reading 0x%x bytes from %hs\n", dwBytesWanted, longhexnumber(dwOffsetH, dwOffsetL).c_str());
    if (bLocal)
        return LocalReadSDCard(dwDiskNr, dwOffsetH, dwOffsetL, buffer, dwBytesWanted, pdwNumberOfBytesRead);
#ifndef _NO_RAPI
    else if (dwOffsetH==0)
        return ITReadSDCard(dwDiskNr, dwOffsetL, buffer, dwBytesWanted, pdwNumberOfBytesRead);
    else {
        printf("WARNING: >4G disks not yet supported for remote sd card\n");
        return false;
    }
#else
    else {
        printf("WARNING: RAPI disabled\n");
        return false;
    }
#endif

}

bool testSector(bool bLocal, DWORD dwDiskNr, DWORD sectornr)
{
    ByteVector buffer(g_sectorsize);

    DWORD dwNumberOfBytesRead;
    g_ignoreerror= true;
    bool bRes= ReadSDCard(bLocal, dwDiskNr, sectornr>>23, sectornr<<9, &buffer[0], buffer.size(), &dwNumberOfBytesRead);
    g_ignoreerror= false;

    if (!bRes) {
        if (g_bVerbose)
            printf("testsector 0x%x / offset %hs : error\n", sectornr, longhexnumber(sectornr>>23, sectornr<<9).c_str());
        return false;
    }

    if (g_bVerbose)
        printf("testsector 0x%x / offset %hs : %d bytes read\n", sectornr, longhexnumber(sectornr>>23, sectornr<<9).c_str(), dwNumberOfBytesRead);
    return dwNumberOfBytesRead==buffer.size();
}

// dwLow is an existing sector, dwHigh is not.
DWORD findInRange(bool bLocal, DWORD dwDiskNr, DWORD dwLow, DWORD dwHigh)
{
    if (dwLow>=dwHigh)
        return 0;
    if (dwLow+1==dwHigh)
        return dwLow;

    DWORD dwMiddle = (dwLow + dwHigh)/2;

    if (testSector(bLocal, dwDiskNr, dwMiddle))
        return findInRange(bLocal, dwDiskNr, dwMiddle, dwHigh);
    else
        return findInRange(bLocal, dwDiskNr, dwLow, dwMiddle);
}

std::string longhexnumber(DWORD dwHigh, DWORD dwLow)
{
    if (dwHigh)
        return stringformat("0x%x%08lx", dwHigh, dwLow);
    else
        return stringformat("0x%x", dwLow);
}

std::string sizestring(double size)
{
    return (size>1024.0*1024*1024*1024)? stringformat("%6.2fT", size/(1024.0*1024*1024*1024))
			: (size>1024.0*1024*1024)? stringformat("%6.2fG", size/(1024.0*1024*1024))
			: (size>1024.0*1024)? stringformat("%6.2fM", size/(1024.0*1024))
			: (size>1024.0)? stringformat("%6.2fk", size/1024.0)
			: stringformat("%6.2f", size);
}
bool FindCardSize(bool bLocal, DWORD dwDiskNr)
{
    DWORD sectornr= 65536;
    if (testSector(bLocal, dwDiskNr, sectornr)) {
        do {
            sectornr *= 2;
        } while (testSector(bLocal, dwDiskNr, sectornr));

        sectornr /= 2;
    }
    else {
        do {
            sectornr /= 2;
        } while (sectornr && !testSector(bLocal, dwDiskNr, sectornr));
    }
    sectornr= findInRange(bLocal, dwDiskNr, sectornr, sectornr*2);
    double size= (double)sectornr*g_sectorsize;
    debug("real nr of sectors: %d  - %hsbyte, 0x%I64x\n", sectornr+1, sizestring(size).c_str(), UInt32x32To64(sectornr, g_sectorsize));
    return true;
}

void Add32To64(DWORD& dwHigh, DWORD& dwLow, DWORD dwOffset)
{
    DWORD dwNewLow= dwLow + dwOffset;
    if (dwNewLow < dwLow )
        dwHigh++;

    dwLow= dwNewLow;
}

bool HexdumpSDCardToStdout(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength)
{
    debug("HexdumpSDCardToStdout(%hs, %d, %hs, 0x%x)\n",
            bLocal?"local":"remote", dwDiskNr, 
            longhexnumber(dwOffsetH, dwOffsetL).c_str(), dwLength);
    while (dwLength)
    {
        ByteVector buffer(g_chunksize);
        DWORD dwWanted= std::min(dwLength+(dwOffsetL&(g_sectorsize-1)), (DWORD)buffer.size());
        if (dwWanted&(g_sectorsize-1))
            dwWanted = (dwWanted|(g_sectorsize-1))+1;

        DWORD dwNumberOfBytesRead;
        if (!ReadSDCard(bLocal, dwDiskNr, dwOffsetH, dwOffsetL, &buffer[0], dwWanted, &dwNumberOfBytesRead))
            return false;

        DWORD dwBufferOffset= dwOffsetL&(g_sectorsize-1);
        DWORD dwNeeded= std::min(dwLength, dwNumberOfBytesRead);

        // debug("ofs=%08lx len=%08lx want=%08lx read=%08lx buf=%08lx  need=%08lx\n", dwOffsetL, dwLength, dwWanted, dwNumberOfBytesRead, dwBufferOffset, dwNeeded);

        bighexdump((uint64_t(dwOffsetH)<<32)|dwOffsetL, ByteVector(&buffer[dwBufferOffset], &buffer[dwBufferOffset+dwNeeded]));

        dwLength -= dwNeeded;
        Add32To64(dwOffsetH, dwOffsetL, dwNeeded);
    }
    return true;
}

bool CopySDCardToFile(bool bLocal, DWORD dwDiskNr, DWORD dwOffsetH, DWORD dwOffsetL, DWORD dwLength, const std::string& outfilename)
{
    debug("CopySDCardToFile(%hs, %d, %hs, 0x%x, %s)\n",
            bLocal?"local":"remote", dwDiskNr, 
            longhexnumber(dwOffsetH, dwOffsetL).c_str(), dwLength, outfilename.c_str());
    HANDLE hDest = CreateFile(outfilename.c_str(), GENERIC_WRITE, FILE_SHARE_READ,
                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hDest)
    {
        error("Unable to open host/destination file");
        return false;
    }

    while (dwLength)
    {
        ByteVector buffer(g_chunksize);

        DWORD dwWanted= std::min(dwLength+(dwOffsetL&(g_sectorsize-1)), (DWORD)buffer.size());
        if (dwWanted&(g_sectorsize-1))
            dwWanted = (dwWanted|(g_sectorsize-1))+1;

        DWORD dwNumberOfBytesRead;
        if (!ReadSDCard(bLocal, dwDiskNr, dwOffsetH, dwOffsetL&~(g_sectorsize-1), &buffer[0], dwWanted, &dwNumberOfBytesRead))
            return false;

        DWORD dwBufferOffset= dwOffsetL&(g_sectorsize-1);
        DWORD dwNeeded= std::min(dwLength, dwNumberOfBytesRead);

        DWORD dwNumWritten;
        if (!WriteFile(hDest, &buffer[dwBufferOffset], dwNeeded, &dwNumWritten, NULL))
        {
            error("Error Writing file");
            return false;
        }

        dwLength -= dwNeeded;

        Add32To64(dwOffsetH, dwOffsetL, dwNeeded);
    }
    CloseHandle (hDest);
    return true;
}

DWORD GetFileSize(const std::string& filename)
{
    HANDLE hSrc = CreateFile(filename.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hSrc)
    {
        error("Unable to open file %hs", filename.c_str());
        return 0;
    }

    DWORD dwSize= GetFileSize(hSrc, NULL);

    CloseHandle(hSrc);

    return dwSize;
}
// ----- get device info -----

bool DeviceIoControl(HANDLE fh, DWORD dwIoControlCode, const ByteVector& inbuf, ByteVector& outbuf)
{
	DWORD cb;
	if (!DeviceIoControl(fh, dwIoControlCode, 
		inbuf.size()?const_cast<BYTE*>(vectorptr(inbuf)):NULL, (DWORD)inbuf.size(), 
		outbuf.size()?vectorptr(outbuf):NULL, (DWORD)outbuf.size(), &cb, NULL))
    {
        if (GetLastError()!=ERROR_INSUFFICIENT_BUFFER)
			return false;

		outbuf.resize(cb);

        if (!DeviceIoControl(fh, dwIoControlCode, 
			inbuf.size()?const_cast<BYTE*>(vectorptr(inbuf)):NULL, (DWORD)inbuf.size(), 
			outbuf.size()?vectorptr(outbuf):NULL, (DWORD)outbuf.size(), &cb, NULL))
		{
            return false;
		}
    }
	return true;
}
#ifndef IOCTL_STORAGE_QUERY_PROPERTY 
// from WinIoCtl.h
typedef enum _STORAGE_PROPERTY_ID {
  StorageDeviceProperty = 0,
  StorageAdapterProperty,
  StorageDeviceIdProperty
} STORAGE_PROPERTY_ID;
typedef enum _STORAGE_QUERY_TYPE {
  PropertyStandardQuery = 0,
  PropertyExistsQuery,
  PropertyMaskQuery,
  PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE;
	typedef struct _STORAGE_PROPERTY_QUERY {
		STORAGE_PROPERTY_ID  PropertyId;
		STORAGE_QUERY_TYPE  QueryType;
		UCHAR  AdditionalParameters[1];
	} STORAGE_PROPERTY_QUERY;
typedef struct _STORAGE_DEVICE_DESCRIPTOR {
  ULONG  Version;
  ULONG  Size;
  UCHAR  DeviceType;
  UCHAR  DeviceTypeModifier;
  BOOLEAN  RemovableMedia;
  BOOLEAN  CommandQueueing;
  ULONG  VendorIdOffset;
  ULONG  ProductIdOffset;
  ULONG  ProductRevisionOffset;
  ULONG  SerialNumberOffset;
  STORAGE_BUS_TYPE  BusType;
  ULONG  RawPropertiesLength;
  UCHAR  RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR;
#define IOCTL_STORAGE_QUERY_PROPERTY   CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
bool GetDeviceDescriptor(HANDLE fh, std::string& descriptor)
{
	ByteVector propquery; propquery.resize(sizeof(STORAGE_PROPERTY_QUERY));
	STORAGE_PROPERTY_QUERY *pq= (STORAGE_PROPERTY_QUERY*)vectorptr(propquery);
	pq->PropertyId= StorageDeviceProperty;
	pq->QueryType= PropertyStandardQuery;
	ByteVector proprpy; proprpy.resize(1024);
    if (!DeviceIoControl(fh, IOCTL_STORAGE_QUERY_PROPERTY, propquery, proprpy)) {
        if (!g_ignoreerror)
            error("IOCTL_STORAGE_QUERY_PROPERTY");
		return false;
    }
	BYTE *p= vectorptr(proprpy);
	STORAGE_DEVICE_DESCRIPTOR *dd= (STORAGE_DEVICE_DESCRIPTOR *)vectorptr(proprpy);

	descriptor=std::string((char*)&p[dd->ProductIdOffset]);
	return true;
}

bool GetDeviceInfoForDrive(char drvchar, DWORD& dwDiskNr, bool& bRemovable)
{
    std::string logicaldrive= stringformat("\\\\.\\%c:", drvchar);;
    HANDLE fh= CreateFile(logicaldrive.c_str(), 0, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (fh==NULL || fh==INVALID_HANDLE_VALUE) {
        if (!g_ignoreerror)
            error("opening %hs", logicaldrive.c_str());
        return false;
    }

    std::string description;
    if (!GetDeviceDescriptor(fh, description))
        return false;
    printf("%c: - %hs\n", drvchar, description.c_str());

    DWORD cb;
    STORAGE_DEVICE_NUMBER devnr;
    if (!DeviceIoControl(fh, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &devnr, sizeof(STORAGE_DEVICE_NUMBER), &cb, NULL)) {
        if (!g_ignoreerror)
            error("IOCTL_STORAGE_GET_DEVICE_NUMBER");
        return false;
    }
    if (devnr.DeviceType!=FILE_DEVICE_DISK) {
        if (!g_ignoreerror)
            printf("device is not a disk\n");
        return false;
    }

    DISK_GEOMETRY geometry;
    if (!DeviceIoControl(fh, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof(geometry), &cb, NULL)) {
        if (!g_ignoreerror)
            error("IOCTL_DISK_GET_DRIVE_GEOMETRY");
        return false;
    }
    double size= (double)geometry.BytesPerSector*geometry.Cylinders.QuadPart*geometry.SectorsPerTrack*geometry.TracksPerCylinder;
    debug("Drive geometry: %hs cyls, %d t/cyl %d s/t %d b/s - %hsbyte\n", longhexnumber(geometry.Cylinders.HighPart, geometry.Cylinders.LowPart).c_str(),
            geometry.TracksPerCylinder, geometry.SectorsPerTrack, geometry.BytesPerSector, sizestring(size).c_str());

    if (g_sectorsize==-1)
        g_sectorsize= geometry.BytesPerSector;

    bRemovable= (geometry.MediaType==RemovableMedia);
    dwDiskNr= devnr.DeviceNumber;

    return true;
}

bool GetDeviceInfoForPhysDrive(DWORD dwDiskNr, bool& bRemovable)
{
    std::string physdrive= stringformat("\\\\.\\PhysicalDrive%d", dwDiskNr&0x7fff);
    HANDLE fh= CreateFile(physdrive.c_str(), GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
    if (fh==NULL || fh==INVALID_HANDLE_VALUE) {
        if (!g_ignoreerror)
            error("opening %hs", physdrive.c_str());
        return false;
    }

    std::string description;
    if (!GetDeviceDescriptor(fh, description))
        return false;
    printf("DISK%d: - %hs\n", dwDiskNr&0x7fff, description.c_str());

    DWORD cb;
    STORAGE_DEVICE_NUMBER devnr;
    if (!DeviceIoControl(fh, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &devnr, sizeof(STORAGE_DEVICE_NUMBER), &cb, NULL)) {
        if (!g_ignoreerror)
            error("IOCTL_STORAGE_GET_DEVICE_NUMBER");
        return false;
    }
    if (devnr.DeviceType!=FILE_DEVICE_DISK) {
        if (!g_ignoreerror)
            printf("device is not a disk\n");
        return false;
    }

    DISK_GEOMETRY geometry;
    if (!DeviceIoControl(fh, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &geometry, sizeof(geometry), &cb, NULL)) {
        if (!g_ignoreerror)
            error("IOCTL_DISK_GET_DRIVE_GEOMETRY");
        return false;
    }
    double size= (double)geometry.BytesPerSector*geometry.Cylinders.QuadPart*geometry.SectorsPerTrack*geometry.TracksPerCylinder;
    debug("Drive geometry: %hs cyls, %d t/cyl %d s/t %d b/s - %hsbyte\n", longhexnumber(geometry.Cylinders.HighPart, geometry.Cylinders.LowPart).c_str(),
            geometry.TracksPerCylinder, geometry.SectorsPerTrack, geometry.BytesPerSector, sizestring(size).c_str());

    if (g_sectorsize==-1)
        g_sectorsize= geometry.BytesPerSector;

    bRemovable= (geometry.MediaType==RemovableMedia);
    dwDiskNr= devnr.DeviceNumber;

    return true;
}
