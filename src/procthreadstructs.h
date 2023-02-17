#ifndef __PROCTHREADSTRUCTS_H__
#define __PROCTHREADSTRUCTS_H__

#include <vector>
// ITGetProcessList
typedef struct tagCEPROCESSENTRY { 
    //DWORD cntUsage; 
    DWORD dwProcessID; 
    //DWORD dwDefaultHeapID; 
    //DWORD dwModuleID; 
    //DWORD cntThreads; 
    //DWORD dwParentProcessID; 
    //DWORD dwFlags; 
    WCHAR szExeFile[MAX_PATH]; 
    WCHAR szCmdLine[MAX_PATH]; 
    DWORD dwMemoryBase;
    DWORD dwAccessKey;

    DWORD dwMemoryUsage;
    //DWORD dwKernelTime;
    //DWORD dwUserTime;
} CEPROCESSENTRY; 
typedef std::vector<CEPROCESSENTRY> CeProcessList;

// ITGetProcessUsageList
typedef struct _tagProcSummaryInfo {
    HANDLE hProc;
    DWORD tKernel;
    DWORD tUser;
    DWORD nThreads;
} ProcSummaryInfo;
typedef std::vector<ProcSummaryInfo> ProcSummaryInfoVector;

// ITGetThreadUsageList
typedef struct _tagThreadSummaryInfo {
    HANDLE hProc;
    HANDLE hThread;
    DWORD dwStartAddr;
    DWORD dwCurPC;
    DWORD dwCurLR;
    DWORD dwCurSP;
    DWORD tKernel;
    DWORD tUser;
    WORD baseprio;
    WORD curprio;
    WCHAR szModname[MAX_PATH];
} ThreadSummaryInfo;
typedef std::vector<ThreadSummaryInfo> ThreadSummaryInfoVector;

// ITGetModuleList
typedef struct tagCEMODULEENTRY { 
    DWORD hLib;
    WCHAR szModuleName[MAX_PATH]; 
    DWORD dwMemoryBase;
    DWORD dwVBase;
    DWORD dwDBase;
    DWORD dwUsage;
} CEMODULEENTRY; 

// ITGetWindowList
typedef struct _tagITSWindowInfo {
    int level;
    HWND hwnd;
    HWND nextsibling;     // dw 00
    HWND parent;          // dw 01
    HWND firstchild;      // dw 02
    WCHAR wtitle[32];     // dw 1a
    WCHAR wclass[32];     // dw 1f.05
    WCHAR wtext[32];      // with WM_GETTEXT

    DWORD msgq;           // dw 1b
    DWORD ime;            // dw 1c
    DWORD style;          // dw 1d
    DWORD exstyle;        // dw 1e
    DWORD usrdata;        // dw 21
    DWORD pid;            // dw 22
    DWORD tid;            // dw 23
    DWORD pid2;           // dw 24
    DWORD wndproc;        // dw 25
    RECT wrect;           // dw 08
    RECT crect;           // dw 0c
    DWORD nlongs;         //  w 1f.00:hi
    DWORD wlongs[8];      // dw 2e

} ITSWindowInfo;

#endif
