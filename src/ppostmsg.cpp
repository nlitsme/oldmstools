/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * 0x0002= WM_DESTROY (0,0)
 * 0x0010= WM_CLOSE (0,0)
 * 0x000A= WM_ENABLE (fEnable, 0)
 * 0x0012= WM_QUIT (nExitCode, 0)
 * 0x0111= WM_COMMAND (wNotify<<16 | wId, hWndCtl) 
 *     BN_CLICKED = 0
 *
 *
 * todo: add parser to pass struct contents, like this:
 *
 * { dw:0x124, w:0x1234, w:0, {"ptrtostring"} , sz32:"fixedstring" }
 *
 * example usage: 
 * ppostmsg -w Listview 0x104b 0  -rl 44 { dw:0 dw:2 }
 * should return info about the item at position 2
 * 
 *
 * done: add option to send string as many 'WM_CHAR' messages
 * todo: add option to use hProc, or hWnd in getwindowlist
 *
 */
#include <util/wintypes.h>
#ifdef WINCEPOSTMSG
#include "itsutils.h"
#include "wintrace.h"
#include "dllversion.h"
#include <util/rapitypes.h>
#endif
#include "debug.h"
#include "stringutils.h"
#include "args.h"
#include "ptrutils.h"
#include "vectorutils.h"
#include <stdio.h>
#include <string.h>
#ifdef WIN32POSTMSG
#include <winuser.h>
#endif

#ifdef WIN32POSTMSG
#include "procthreadstructs.h"  // ITSWindowInfo
#endif
#ifdef WINCEPOSTMSG
struct show_value_map {
    DWORD dwShowValue;
    std::string command;
};

show_value_map showvalues[]= {

{ SW_HIDE             , "hide" },
{ SW_SHOWNORMAL       , "shownormal" },
{ SW_SHOWNOACTIVATE   , "shownoactivate" },
{ SW_SHOW             , "show" },
{ SW_MINIMIZE         , "minimize" },
{ SW_SHOWNA           , "showna" },
{ SW_SHOWMAXIMIZED    , "showmaximized" },
{ SW_MAXIMIZE         , "maximize" },
{ SW_RESTORE          , "restore" },
{ SW_SETFOREGROUND    , "setforeground" },
{ SW_SETACTIVE        , "setactive" },
{ SW_SETCAPTURE       , "setcapture" },
{ SW_BRINGTOTOP       , "bringtotop" },
{ SW_DRAWMENUBAR      , "drawmenubar" },
{ SW_DESTROYWINDOW    , "destroywindow" },
{ SW_UPDATEWINDOW     , "updatewindow" },
{ SW_HIDECARET        , "hidecaret" },
{ SW_SHOWCARET        , "showcaret" },
{ SW_SETFOCUS         , "setfocus" },
{ SW_ENABLEWINDOW     , "enablewindow" },
{ SW_DISABLEWINDOW    , "disablewindow" },
{ SW_ENDDIALOGOK      , "enddialogok" },
{ SW_ENDDIALOGCANCEL  , "enddialogcancel" },
{ SW_ENDDIALOGCLOSE   , "enddialogclose" },
{ SW_ENDDIALOGABORT   , "enddialogabort" },
};
#define N_SHOWVALS (sizeof(showvalues)/sizeof(*showvalues))
#endif

int g_verbose= 0;

typedef std::vector<ITSWindowInfo> WindowInfoList;
#ifdef WINCEPOSTMSG
HANDLE ITGetProcessHandle(const std::string& processname);
bool ITTraceWindow(int cmd, HWND hWnd);
#endif
bool ITGetWindowList(WindowInfoList& list, HWND hwnd, HANDLE hproc, bool bVerbose);
bool ITGetWindowStruct(DWORD hWindow, ByteVector& v);
HWND ITGetForegroundWindow();
bool ITGetForegroundInfo(DWORD *p);
void fill_windowinfo(HWND hWnd, int level, bool bVerbose, ITSWindowInfo &info);
HWND ITFindWindow(const std::string& classname, const std::string& windowname);
bool ITShowWindow(HWND hWnd, DWORD dwShow);
bool ITSendMessage(HWND hWnd, DWORD nMsg, DWORD wParam, DWORD lParam, DWORD dwFlags, 
        const ByteVector &indata, DWORD *plResult, ByteVector &outdata);
void ListWindows(HANDLE hProc, BOOL bVerbose);
void ShowWindowInfo(HWND hWnd);

#ifdef WIN32POSTMSG
#define SMGS_WPARAM_IS_INPUTOFS   1
#define SMGS_WPARAM_IS_OUTPUTOFS  2
#define SMGS_LPARAM_IS_INPUTOFS   4
#define SMGS_LPARAM_IS_OUTPUTOFS  8
#define SMGS_POSTMESSAGE         16
#define SMGS_WAITWINDOW          32
#endif
bool ParseParamString(const char *arg, ByteVector& wParamSend, DWORD& wParam)
{
    char *p= NULL;
    DWORD value= strtoul(arg, &p, 0);
    if (p!=arg) {
        wParam= value;
        return true;
    }

    wParamSend.resize(strlen(arg));
    memcpy(vectorptr(wParamSend), arg, wParamSend.size());
    return true;
}

#ifdef WIN32POSTMSG
char *GetAppPath()
{
    static char appname[1024];
    if (!GetModuleFileName(NULL, appname, 1024))
        return NULL;

    return appname;
}
#endif

DWORD ParseMessage(const char *msg)
{
    char *p= NULL;
    DWORD dwMsg= strtoul(msg, &p, 0);
    if (p!=msg)
        return dwMsg;

    std::string approot= GetAppPath();
    approot.resize(approot.find_last_of('\\'));
    approot += "\\its_windows_message_list.txt";
    FILE *f= fopen(approot.c_str(), "r");
    if (f==NULL) 
        return 0;


    char linebuf[256];
    while (fgets(linebuf, sizeof(linebuf), f))
    {
        if (isspace(linebuf[0]))
            continue;
        char *p= strtok(linebuf, "\t \r\n");    // get message class ( 'WM' )
        if (p==NULL || *p==0)
            continue;
        p= strtok(NULL, "\t \r\n");             // get message nr
        if (p==NULL || *p==0)
            continue;
        DWORD dwMsg= strtoul(p, 0, 0);
        p= strtok(NULL, "\t \r\n");             // get message name
        if (p==NULL || *p==0)
            continue;
        if (stringicompare(std::string(msg), std::string(p))==0)
        {
            fclose(f);
            return dwMsg;
        }
    }
    fclose(f);
    return 0;
}
void usage()
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    printf("Usage: psendmsg [options]  msg wparam lparam\n");
    printf("    numbers can be specified as 0x1234abcd\n");
    printf("    either specify a handle, or a name+class\n");
    printf("    -p               POST instead of SEND\n");
    printf("    -l               list all windows\n");
    printf("    -v               more info in list\n");
    printf("    -W               after message, wait until window disappears\n");
    printf("    -show            show window\n");
    printf("    -hide            hide window\n");
    printf("    -t CMD           trace window messages\n");
    printf("       CMD: start, stop, add, del, addproc, delproc\n");
    printf("    -n NAME          processname, use with -t addproc\n");
    printf("    -h HANDLE        use window handle - default = foreground\n");
    printf("    -w WINDOWNAME    find window by name\n");
    printf("    -c CLASSNAME     limit find to classname\n");
    printf("    -rw SIZE         wparam is buffer of SIZE bytes\n");
    printf("    -rl SIZE         lparam is buffer of SIZE bytes\n");
    printf("    wparam and lparam may be specified as hexnumber\n");
    printf("    or as quoted string\n");
#ifdef WINCEPOSTMSG
    printf("    --WNDCOMMAND     one of:\n");
    size_t col=0;
    for (size_t i=0 ; i<N_SHOWVALS ; i++) {
        if (col) {
            if (col+1+showvalues[i].command.size()>=80) {
                putchar('\n');
                col=0;
            }
            else {
                putchar(' ');
                col++;
            }
        }
        printf("%s", showvalues[i].command.c_str());
        col += showvalues[i].command.size();
    }
    printf("\n");
#endif
}
#ifdef WINCEPOSTMSG
DWORD getShowValue(const char*name)
{
    for (size_t i=0 ; i<N_SHOWVALS ; i++)
    {
        if (showvalues[i].command==name) 
            return showvalues[i].dwShowValue;
    }
    return (DWORD)-1;
}
#endif
int main( int argc, char *argv[])
{
    DebugStdOut();

    int res= 0;
    HWND hWnd=0;
    std::string windowname;
    std::string classname;

    std::string processname;

#ifdef WINCEPOSTMSG
    HANDLE hProc= 0;
    std::string tracecmdstr;
    int tracecmd=-1;
#endif
    bool do_list_windows= false;
    bool do_window_info= false;

    DWORD nMsg=0;
    DWORD wParam=0;
    DWORD lParam=0;
    DWORD dwFlags= 0;

    ByteVector wParamSend;
    ByteVector lParamSend;
    DWORD dwResultWParam= 0;
    DWORD dwResultLParam= 0;
    bool bDoShowWindow= false;
    DWORD dwShowValue= -1;
//    const char *charstring=NULL;

    int argsfound=0;
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 'p': dwFlags |= SMGS_POSTMESSAGE; break;
            case 'l': do_list_windows= true; break;
            case 'v': g_verbose += countoptionmultiplicity(argv, i, argc); 
                      break;
            case 'h': if (strcmp(argv[i], "-hide")==0) {
                          bDoShowWindow=true;
                          dwShowValue= SW_HIDE;
                      }
                      else if (i+1>=argc) {
                          usage();
                          return 1;
                      }
                      else {
                          HANDLEULOPTION(hWnd, HWND); 
                      }
                      break;
#ifdef WINCEPOSTMSG
            case 'n': HANDLESTROPTION(processname); break;
            case 't': HANDLESTROPTION(tracecmdstr);
                      if (tracecmdstr=="add")   tracecmd= WND_ADD_WINDOW;
                      else if (tracecmdstr=="del")   tracecmd= WND_DEL_WINDOW;
                      else if (tracecmdstr=="addproc")   tracecmd= WND_ADD_PROCESS;
                      else if (tracecmdstr=="delproc")   tracecmd= WND_DEL_PROCESS;
                      else if (tracecmdstr=="start") tracecmd= WND_START_TRACE;
                      else if (tracecmdstr=="stop")  tracecmd= WND_STOP_TRACE;
                      else {
                          printf("unknown trace command: %s\n", tracecmdstr.c_str());
                          return 1;
                      }
                      break;
#endif
            case 's': if (strcmp(argv[i]+1, "show")==0) {
                          bDoShowWindow= true;
                          dwShowValue= SW_SHOW;
                      }
                      else if ( argv[i][2]==0 && (i+1)<argc) {
                          BV_AppendString(wParamSend, argv[i+1]);
                          i++;
                      }
                      break;
            case 'w': HANDLESTROPTION(windowname); break;
            case 'W': dwFlags |= SMGS_WAITWINDOW; break;
            case 'c': HANDLESTROPTION(classname); break;
            case 'r': 
                      {
                      char *arg= argv[i]+3;
                      switch(argv[i][2]) {
                          case 'w': HANDLEULOPTION2(dwResultWParam, DWORD); break;
                          case 'l': HANDLEULOPTION2(dwResultLParam, DWORD); break;
                          default:
                                    printf("unknown option %s\n", argv[i]);
                                    usage();
                                    return 1;
                      }
                      }
                      break;
#ifdef WINCEPOSTMSG
            case '-':
                      dwShowValue= getShowValue(argv[i]+2);
                      if (dwShowValue!=(DWORD)-1)
                          bDoShowWindow= true;
                      break;
#endif
            default:
                printf("unknown option %s\n", argv[i]);
                usage();
                return 1;
        }
        else switch (argsfound++)
        {
            case 0: nMsg= ParseMessage(argv[i]); break;
            case 1: if (!dwResultWParam) {
                        ParseParamString(argv[i], wParamSend, wParam);
                        break;
                    }
                    /* fall through */
            case 2: if (!dwResultLParam) {
                        ParseParamString(argv[i], lParamSend, lParam);
                        break;
                    }
            default:
                    printf("unknown argument %d - %s\n", argsfound-1, argv[i]);
                    usage();
                    return 1;
        }
    }
    if (argsfound==0 && !bDoShowWindow)
    {
        do_window_info= true;;
    }

    if (dwResultWParam && wParam) {
        debug("cannot specify both value, and return buffer for wparam\n");
        return 1;
    }
    if (dwResultLParam && lParam) {
        debug("cannot specify both value, and return buffer for lparam\n");
        return 1;
    }

#ifdef WINCEPOSTMSG
    if (tracecmd!=-1)
        g_wantstream= false;
#endif

#ifdef WINCEPOSTMSG
    CheckITSDll();
#endif

    if (do_list_windows) {
        ListWindows(0, TRUE);
        return 0;
    }

#ifdef WINCEPOSTMSG
    if (tracecmd==WND_START_TRACE || tracecmd==WND_STOP_TRACE) {
        ITTraceWindow(tracecmd, 0);
        return 0;
    }
#endif
    if (classname.size() || windowname.size())
        hWnd= ITFindWindow(classname, windowname);
#ifdef WINCEPOSTMSG
    else if (tracecmd==WND_ADD_PROCESS || tracecmd==WND_DEL_PROCESS) {
        if (!processname.empty())
            hProc= ITGetProcessHandle(processname);
        else
            hProc= (HANDLE)hWnd;
    }
#endif
    else if (hWnd==0)
        hWnd= ITGetForegroundWindow();
    else {
        // use specified hwnd
    }

#ifdef WINCEPOSTMSG
    if (hWnd==0 && tracecmd!=WND_ADD_PROCESS && tracecmd!=WND_DEL_PROCESS) {
        debug("Window not found\n");
        return 1;
    }
    if (tracecmd==WND_ADD_WINDOW || tracecmd==WND_DEL_WINDOW) {
        ITTraceWindow(tracecmd, hWnd);
        return 0;
    }
    else if (tracecmd==WND_ADD_PROCESS || tracecmd==WND_DEL_PROCESS) {
        if (hProc==0) {
            debug("process not found\n");
            return 1;
        }
        ITTraceWindow(tracecmd, (HWND)hProc);
        return 0;
    }
#endif

    if (do_window_info) {
        ShowWindowInfo(hWnd);
        return 0;
    }
    if (bDoShowWindow) {
        ITShowWindow(hWnd, dwShowValue);
    }
//   else if (charstring) {
//       for (const char *p= charstring ; *p ; p++) {
//           ByteVector senddata;
//           ByteVector replydata;
//           DWORD lresult= 0;
//           if (!ITSendMessage(hWnd, nMsg, *p, 0, dwFlags, senddata, &lresult, replydata)) {
//               debug("Error sending char %d : %02x\n", p-charstring, *p);
//               res= 1;
//               break;
//           }
//       }
//   }
    else {
        ByteVector senddata= wParamSend; BV_AppendVector(senddata, lParamSend);
        ByteVector replydata; replydata.resize(dwResultWParam+dwResultLParam);

        if (!wParamSend.empty()) {
            wParam= 0;
            dwFlags |= SMGS_WPARAM_IS_INPUTOFS;
        }
        if (dwResultWParam) {
            wParam= 0;
            dwFlags |= SMGS_WPARAM_IS_OUTPUTOFS;
        }
        if (!lParamSend.empty()) {
            lParam= wParamSend.size();
            dwFlags |= SMGS_LPARAM_IS_INPUTOFS;
        }
        if (dwResultLParam) {
            lParam= dwResultWParam;
            dwFlags |= SMGS_LPARAM_IS_OUTPUTOFS;
        }

        DWORD lresult=0;
        if (!ITSendMessage(hWnd, nMsg, wParam, lParam, dwFlags, senddata, &lresult, replydata)) {
            debug("Error sending message\n");
            res= 1;
        }

        ByteVector wParamResult; wParamResult.resize(dwResultWParam);
        memcpy(vectorptr(wParamResult), vectorptr(replydata), wParamResult.size());

        ByteVector lParamResult; lParamResult.resize(dwResultLParam);
        memcpy(vectorptr(lParamResult), vectorptr(replydata)+lParam, lParamResult.size());

        debug("reply: %08lx\n", lresult);
        if (!wParamResult.empty()) debug("  wparam: %hs\n", hexdump(wParamResult).c_str());
        if (!lParamResult.empty()) debug("  lparam: %hs\n", hexdump(lParamResult).c_str());
    }
#ifdef WINCEPOSTMSG
    StopItsutils();
#endif
    return res;
}

#ifdef WINCEPOSTMSG
HANDLE ITGetProcessHandle(const std::string& processname)
{
    std::Wstring wprocname= ToWString(processname);
    DWORD insize= (wprocname.size()+1)*sizeof(WCHAR);
    WCHAR *inbuf= (WCHAR*)RapiAlloc(insize);

    std::copy(wprocname.begin(), wprocname.end(), inbuf);
    inbuf[wprocname.size()]= 0;

    DWORD outsize=0;
    HANDLE *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetProcessHandle",
            insize, (BYTE*)inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL) 
    {
        error(res, "ITGetProcessHandle");
        return INVALID_HANDLE_VALUE;
    }

    HANDLE hproc= *outbuf;

    RapiFree(outbuf);

    return hproc;
}
#endif
const char*wndtag(HWND wnd, HWND fgnd, DWORD *info)
{
    if (wnd==fgnd) return "*";
    if (wnd==(HWND)info[0]) return "@";
    if (wnd==(HWND)info[1]) return "+";
    if (wnd==(HWND)info[2]) return "^";
    if (wnd==(HWND)info[3]) return ">";
    return " ";
}
void PrintMemStruct(uint8_t *data, size_t datasize)
{
    while (datasize>8) {
        uint32_t ofs= get32le(data);
        uint32_t size= get32le(data+4);
        if (datasize<8+size)
            break;
        printf("%08x: %s%s%s\n", ofs,
                hexdump(data+8, size/4, 4).c_str(),
                (size%4)?" " : "",
                (size%4) ? hexdump(data+8+size/4, size%4).c_str() : "");

        datasize -= 8 + size;
        data += 8 + size;
    }
}

void ListWindows(HANDLE hProc, BOOL bVerbose)
{
    HWND hwndForeground= ITGetForegroundWindow();
    DWORD info[9]; memset(info, 0, sizeof(info));
#ifdef WINCEPOSTMSG
    ITGetForegroundInfo(info);
    if (g_verbose) {
        printf("fgnd=%08x active=%08x focus=%08x menu=%08x kbd=%08x\n",
                hwndForeground, info[0], info[1], info[2], info[3]);
        printf("conversion=%d sentence=%d open=%d compstr=%d  kbdlayout=%08x\n",
                info[4], info[5], info[6], info[7], info[8]);
    }
#endif
    WindowInfoList list;
    if (!ITGetWindowList(list, 0, hProc, bVerbose))
        return;

    for (size_t i=0 ; i<list.size() ; i++)
    {
        std::string title= list[i].wtitle[0]==0xFFFF ? stringformat("RSC<%04x>", list[i].wtitle[1]) : ToString(list[i].wtitle);
        if (g_verbose) {
            printf("%08lx%s %08lx %08lx %*s%-32s %-16s%*s %s\n", 
                list[i].hwnd,
                wndtag(list[i].hwnd,hwndForeground, info),
                list[i].pid,
                list[i].usrdata,
                  list[i].level*3, "", 
                ToString(list[i].wclass).c_str(), title.c_str(),
                  (4-list[i].level)*3, "", 
                hexdump((BYTE*)list[i].wlongs, std::min(list[i].nlongs,(DWORD)8), 4).c_str());
            if (memcmp(list[i].wtitle, list[i].wtext, 64)!=0) {
                std::string text= list[i].wtext[0]==0xFFFF ? stringformat("RSC<%04x>", list[i].wtext[1]) : ToString(list[i].wtext);
                printf("     %s\n", text.c_str());
            }
#ifdef WINCEPOSTMSG
            if (g_verbose>1) {
                ByteVector v;
                if (ITGetWindowStruct((DWORD)list[i].hwnd, v))
                    PrintMemStruct(&v[0], v.size());

            }
#endif
        }
        else
            printf("%08lx%s %*s%-32s %-16s\n", 
                list[i].hwnd,
                wndtag(list[i].hwnd,hwndForeground, info),
                  list[i].level*3, "", 
                ToString(list[i].wclass).c_str(), title.c_str());
    }
}
void ShowWindowInfo(HWND hWnd)
{
#ifdef WINCEPOSTMSG
    WindowInfoList list;
    if (!ITGetWindowList(list, hWnd, 0, TRUE))
        return;

    ITSWindowInfo wi;
    memset(&wi, 0, sizeof(wi));
    for (unsigned i=0 ; i<list.size() ; i++)
        if (list[i].hwnd==hWnd) {
            wi= list[i];
            break;
        }
    if (wi.hwnd!=hWnd) {
        printf("window info not found for %08x\n", hWnd);
        return;
    }
#endif
#ifdef WIN32POSTMSG
    ITSWindowInfo wi;
    fill_windowinfo(hWnd, 0, TRUE, wi);
#endif
    printf("nextsibling=%08lx\n", wi.nextsibling);
    printf("parent=%08lx\n", wi.parent);
    printf("firstchild=%08lx\n", wi.firstchild);
    printf("wtitle[32]='%s'\n", ToString(wi.wtitle).c_str());
    printf("wclass[32]='%s'\n", ToString(wi.wclass).c_str());
    printf("wtext[32]='%s'\n", ToString(wi.wtext).c_str());

    printf("msgq=%08lx\n", wi.msgq);
    printf("ime=%08lx\n", wi.ime);
    printf("style=%08lx\n", wi.style);
    printf("exstyle=%08lx\n", wi.exstyle);
    printf("usrdata=%08lx\n", wi.usrdata);
    printf("pid=%08lx\n", wi.pid);
    printf("tid=%08lx\n", wi.tid);
    printf("pid2=%08lx\n", wi.pid2);
    printf("wndproc=%08lx\n", wi.wndproc);
    printf("wrect=(%d,%d,%d,%d)\n", wi.wrect.left, wi.wrect.top, wi.wrect.right, wi.wrect.bottom);
    printf("crect=(%d,%d,%d,%d)\n", wi.crect.left, wi.crect.top, wi.crect.right, wi.crect.bottom);
    printf("nlongs=%d:", wi.nlongs);
    for (unsigned i=0 ; i<wi.nlongs && i<8 ; i++)
        printf(" %08lx", wi.wlongs[i]);
    printf("\n");
}

#ifdef WINCEPOSTMSG
HWND ITFindWindow(const std::string& classname, const std::string& windowname)
{
    FindWindowParams inbuf;
    DWORD insize= sizeof(inbuf);

    std::Wstring wcls= ToWString(classname);
    std::Wstring wwnd= ToWString(windowname);

    std::copy(wcls.begin(), wcls.begin()+std::min(wcls.size()+1, size_t(MAX_PATH-1)), inbuf.szClassName);
    inbuf.szClassName[MAX_PATH-1]= 0;

    std::copy(wwnd.begin(), wwnd.begin()+std::min(wwnd.size()+1, size_t(MAX_PATH-1)), inbuf.szWindowName);
    inbuf.szWindowName[MAX_PATH-1]= 0;

    DWORD outsize=0;
    FindWindowResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITFindWindow",
            insize, (BYTE*)&inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITFindWindow(cls:'%s', wnd:'%s')", classname.c_str(), windowname.c_str());
        return 0;
    }

    HWND hWnd= outbuf->hWnd;

    RapiFree(outbuf);

    return hWnd;
}
HWND ITGetForegroundWindow()
{
    DWORD outsize=0;
    GetForegroundWindowResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetForegroundWindow",
            0, NULL,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITGetForegroundWindow");
        return 0;
    }

    HWND hWnd= outbuf->hwnd;

    RapiFree(outbuf);

    return hWnd;
}
bool ITGetForegroundInfo(DWORD *p)
{
    DWORD outsize=0;
    GetForegroundInfoResult *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITGetForegroundInfo",
            0, NULL,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITGetForegroundInfo");
        return FALSE;
    }

    memcpy(p, outbuf, 9*4);

    RapiFree(outbuf);

    return TRUE;
}

bool ITGetWindowList(WindowInfoList& list, HWND hwnd, HANDLE hproc, bool bVerbose)
{
    DWORD outsize=0;
    GetWindowListResult *outbuf=NULL;
    GetWindowListParams inbuf;

    inbuf.hWnd= (DWORD)hwnd;
    inbuf.hProc= (DWORD)hproc;
    inbuf.bVerbose= bVerbose;

    HRESULT res= ItsutilsInvoke("ITGetWindowList",
            sizeof(inbuf), (BYTE*)&inbuf,
            &outsize, (BYTE**)&outbuf);
    if (res || outbuf==NULL)
    {
        error(res, "ITGetWindowList");
        return false;
    }
    list.resize(outbuf->count);
    memcpy(vectorptr(list), outbuf->info, outbuf->count*sizeof(ITSWindowInfo));

    RapiFree(outbuf);

    return true;
}

bool ITShowWindow(HWND hWnd, DWORD dwShow)
{
    ShowWindowParams request;
    DWORD reqsize= sizeof(request);

    request.hWnd= hWnd;
    request.dwShow= dwShow;

    DWORD repsize=0;

    HRESULT res= ItsutilsInvoke("ITShowWindow",
            reqsize, (BYTE*)&request,
            &repsize, NULL);
    if (res) 
    {
        error(res, "ITShowWindow");
        return false;
    }
    return true;

}
bool ITSendMessage(HWND hWnd, DWORD nMsg, DWORD wParam, DWORD lParam, DWORD dwFlags, 
        const ByteVector &indata, DWORD *plResult, ByteVector &outdata)
{
    SendMessageParams *request= NULL;
    DWORD reqsize= PTR_DIFF(request, request->buf+indata.size());
    request= (SendMessageParams*)RapiAlloc(reqsize);

    request->hWnd= hWnd;
    request->nMsg= nMsg;
    request->wParam= wParam;
    request->lParam= lParam;
    if (!indata.empty())
        memcpy(request->buf, vectorptr(indata), indata.size());
    request->dwResultAlloc= outdata.size();
    request->dwFlags= dwFlags;

    DWORD repsize=0;
    SendMessageResult *reply= NULL;

    HRESULT res= ItsutilsInvoke("ITSendMessage",
            reqsize, (BYTE*)request,
            &repsize, (BYTE**)&reply);
    if (res) 
    {
        error(res, "ITSendMessage");
        return false;
    }
    if (reply==NULL)
    {
        debug("ITSendMessage: reply=NULL, repsize=%d\n", repsize);
        return false;
    }
    *plResult= reply->lResult;

    DWORD outresult= repsize - PTR_DIFF(reply, reply->buf);
    if (outdata.size() != outresult)
        debug("WARNING: ITSendMessage: outsize(%d) != resultsize(%d)\n", outdata.size(), outresult);
    if (!outdata.empty()) {
        outdata.resize(outresult);
        memcpy(vectorptr(outdata), reply->buf, outdata.size());
    }

    RapiFree(reply);
    return true;
}

bool ITTraceWindow(int cmd, HWND hWnd)
{
    TraceWindowParams request;
    DWORD reqsize= sizeof(request);

    request.cmd= cmd;
    request.hWnd= (DWORD)hWnd;

    DWORD repsize=0;

    HRESULT res= ItsutilsInvoke("ITTraceWindow",
            reqsize, (BYTE*)&request,
            &repsize, NULL);
    if (res) 
    {
        error(res, "ITTraceWindow");
        return false;
    }
    return true;
}
bool ITGetWindowStruct(DWORD hWindow, ByteVector& v)
{
    DWORD outsize=0;
    BYTE *outbuf=NULL;
    GetWindowStructParams in;
    in.hWnd= hWindow;
    HRESULT res= ItsutilsInvoke("ITGetWindowStruct",
            sizeof(in), (BYTE*)&in, &outsize, (BYTE**)&outbuf);

    if (res || outbuf==NULL)
    {
        error(res, "ITGetWindowStruct");
        return false;
    }
    v.resize(outsize);
    memcpy(&v[0], outbuf, outsize);

    RapiFree(outbuf);
    
    return true;
}
#endif
#ifdef WIN32POSTMSG

HWND ITFindWindow(const std::string& classname, const std::string& windowname)
{
    return FindWindowEx(NULL, NULL, classname.empty() ? NULL : classname.c_str(), windowname.empty() ? NULL : windowname.c_str());
}
HWND ITGetForegroundWindow()
{
    return GetForegroundWindow();
}
void fill_windowinfo(HWND hWnd, int level, bool bVerbose, ITSWindowInfo &info)
{
    info.level = level;
    info.hwnd= hWnd;           // HWND  
    info.nextsibling= GetWindow(hWnd, GW_HWNDNEXT);    // HWND  dw 00
    info.parent= GetWindow(hWnd, GW_OWNER);       // HWND  dw 01
    info.firstchild= GetWindow(hWnd, GW_CHILD);   // HWND  dw 02
    // todo: info.wtitle
    GetClassNameW(hWnd, info.wclass, 32);          // WCHAR[32] dw 1f.05
    if (bVerbose) {
        GetWindowTextW(hWnd, info.wtext, 32);         // WCHAR[32] dw 1a
        info.wtext[31]=0;
    }
    else
        info.wtext[0]=0;
                             
    // NOTE: problem with win64: GWL_USERDATA\|GWL_HINSTANCE\|GWL_WNDPROC\|GWL_HINSTANCE  are no longer defined.
    info.msgq=0;         // DWORD dw 1b
    info.ime=0;          // DWORD dw 1c
    info.style= GetWindowLong(hWnd, GWL_STYLE);      // DWORD dw 1d
    info.exstyle= GetWindowLong(hWnd, GWL_EXSTYLE);  // DWORD dw 1e
    info.usrdata= GetWindowLong(hWnd, GWLP_USERDATA); // DWORD dw 21
    info.pid= GetWindowLong(hWnd, GWLP_HINSTANCE);    // DWORD dw 22
    info.tid=0;            // DWORD dw 23
    GetWindowThreadProcessId(hWnd, &info.pid2);      // DWORD dw 24
    info.wndproc= GetWindowLong(hWnd, GWLP_WNDPROC);  // DWORD dw 25
    GetWindowRect(hWnd, &info.wrect);                // RECT  dw 08
    GetClientRect(hWnd, &info.crect);                // RECT  dw 0c
    info.nlongs= GetClassLong(hWnd, GCL_CBWNDEXTRA); // DWORD dw 1f.00:hi
    // DWORD[8] dw 2e
    for (int i=0 ; i<8 ; i++)
        info.wlongs[i]= GetWindowLong(hWnd, i);
}
struct enuminfo {
    WindowInfoList *list;
    int level;
    HANDLE hProc;
    HWND hWnd;
    BOOL bVerbose;
};

BOOL WINAPI enumchildren(HWND hWnd, LPARAM lParam);
BOOL WINAPI addtolist(HWND hWnd, LPARAM lParam)
{
    enuminfo *p=  reinterpret_cast<enuminfo*>(lParam);
    // int GetWindowTextLength(hWnd)
    // int GetWindowText(hWnd, LPTSTR, strsize)
    //+ BOOL GetClientRect(hWnd, RECT*)
    //+ BOOL GetWindowRect(hWnd, RECT*)
    // DWORD GetWindowLong(hWnd, n)
    //    GWL_WNDPROC
    //    GWL_HINSTANCE
    //    GWL_HWNDPARENT
    //+   GWL_STYLE
    //+   GWL_EXSTYLE
    //    GWL_USERDATA
    //    GWL_ID 
    // DWORD GetClassLong(IN HWND hWnd, IN int nIndex);
    //    CL_MENUNAME
    //    GCL_HBRBACKGROUND
    //    GCL_HCURSOR
    //    GCL_HICON
    //    GCL_HMODULE
    //    GCL_CBWNDEXTRA
    //    GCL_CBCLSEXTRA
    //    GCL_WNDPROC
    //    GCL_STYLE
    //    GCW_ATOM
    //    GCL_HICONSM
    // HWND GetParent(hWnd)
    // int GetClassName(hWnd, LPTSTR, maxsize)
    // HWND GetWindow(hWnd, n)
    //    GW_HWNDFIRST
    //    GW_HWNDLAST
    //    GW_HWNDNEXT
    //    GW_HWNDPREV
    //    GW_OWNER
    //    GW_CHILD 
    // UINT GetWindowModuleFileName(hWnd, LPTSTR, maxsize)
    //
    // GetWindowInfo(hWnd, WINDOWINFO*)

    if ((p->hWnd==0 && p->hProc==0) || (p->hWnd==hWnd) || (p->hProc==(HANDLE)GetWindowLong(hWnd, GWLP_HINSTANCE))) {
        p->list->resize(p->list->size()+1);
        fill_windowinfo(hWnd, p->level, p->bVerbose, p->list->back());
    }

    enumchildren(hWnd, lParam);

    return TRUE;// continue enumeration
}
BOOL WINAPI enumchildren(HWND hWnd, LPARAM lParam)
{
    enuminfo *p=  reinterpret_cast<enuminfo*>(lParam);

    p->level++;

    if (!EnumChildWindows(hWnd, addtolist, lParam)) {
        //error("EnumChildWindows");
    }

    p->level--;

    return TRUE;// continue enumeration
}
bool ITGetWindowList(WindowInfoList& list, HWND hwnd, HANDLE hproc, bool bVerbose)
{
    enuminfo info;
    info.list= &list;
    info.hWnd= hwnd;
    info.hProc= hproc;
    info.bVerbose= bVerbose;
    info.level= 0;
    if (!EnumWindows(enumchildren, reinterpret_cast<LPARAM>(&info)))
    {
        error("EnumWindows");
        return false;
    }
    return true;
}
bool ITShowWindow(HWND hWnd, DWORD dwShow)
{
    return FALSE!=ShowWindow(hWnd, dwShow);
}
DWORD send_string(bool bPost, HWND hWnd, DWORD nMsg, const char* str, DWORD lParam)
{
    DWORD lRes= 0;
    for (const char*p= str ; *p ; p++)
    {
        if (bPost) {
            if (!PostMessage(hWnd, nMsg, *p, lParam)) {
                lRes= GetLastError();
                break;
            }
        }
        else {
            lRes= SendMessage(hWnd, nMsg, *p, lParam);
        }
    }
    return lRes;
}
bool is_char_message(DWORD nMsg)
{
    return nMsg>=WM_KEYFIRST && nMsg<=WM_KEYLAST;
}
bool ITSendMessage(HWND hWnd, DWORD nMsg, DWORD inpwParam, DWORD inplParam, DWORD dwFlags, 
        const ByteVector &indata, DWORD *plResult, ByteVector &outdata)
{
    WPARAM wParam = inpwParam;
    if (dwFlags&SMGS_WPARAM_IS_INPUTOFS)
        wParam += (DWORD)vectorptr(indata);
    else if (dwFlags&SMGS_WPARAM_IS_OUTPUTOFS)
        wParam += (DWORD)vectorptr(outdata);

    LPARAM lParam = inplParam;
    if (dwFlags&SMGS_LPARAM_IS_INPUTOFS)
        lParam += (DWORD)vectorptr(indata);
    else if (dwFlags&SMGS_LPARAM_IS_OUTPUTOFS)
        lParam += (DWORD)vectorptr(outdata);

    if (is_char_message(nMsg) && (dwFlags&SMGS_WPARAM_IS_INPUTOFS)) {
        *plResult= send_string(dwFlags&SMGS_POSTMESSAGE, hWnd, nMsg, (char*)wParam, lParam);
    }
    else if (dwFlags&SMGS_POSTMESSAGE) {
        debug("PostMessage(%08lx, %08lx, %08lx, %08lx) [%x]\n",
                hWnd, nMsg, wParam, lParam, dwFlags&15);
        if (!PostMessage(hWnd, nMsg, wParam, lParam)) {
            error("PostMessage");
            return false;
        }
    }
    else {
        debug("SendMessage(%08lx, %08lx, %08lx, %08lx) [%x]\n",
                hWnd, nMsg, wParam, lParam, dwFlags&15);
        *plResult= SendMessage(hWnd, nMsg, wParam, lParam);
    }
    if (dwFlags&SMGS_WAITWINDOW) {
        DWORD pid;
        GetWindowThreadProcessId(hWnd, &pid);
        HANDLE hProc= OpenProcess(0,0, pid);
        if (WAIT_TIMEOUT==WaitForSingleObject(hProc, 20000))
            return false;
        CloseHandle(hProc);
    }

    return true;
}
#endif
