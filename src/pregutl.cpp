/* (C) 2003-2007 Willem Jan Hengeveld <itsme@xs4all.nl>
 * Web: http://www.xs4all.nl/~itsme/
 *      http://wiki.xda-developers.com/
 *
 * $Id$
 *
 * bug:  specifying invalid string with '-d'  can cause whole registry to be deleted
 *     pregutl -d hklm\software\somekey  0000101a
 */

// NOTE: boost 1.30 -> 1.33  : changed from regex_match param boost::regbase::icase 
//    to regex constructor param boost::regex_constants::icase

#include <util/wintypes.h>
#include "debug.h"
#include "args.h"
#include <stdio.h>
#include <string>
#include <map>
#include <vector>
#include "stringutils.h"
#include "vectorutils.h"

#ifndef _WIN32_WCE
#include "FileFunctions.h"
#endif

#ifdef WINCEREGUTL
#ifndef _WIN32_WCE
// include only for win32 version
#include <util/rapitypes.h>
#include "dllversion.h"
#endif
#endif

#include "regvalue.h"
#include "regkey.h"
#include "regfileparser.h"
// todo:
//    - support 'REGEDIT4' fileformat header.
//    - support unicode files
//    - change 'r' option in non-recursive option
//    - add option to choose how to mix keys and values.
//         ( full cross product, or values per key. )
//    - support comments at end of line
//    - support [-HKEY\path]  delete registry key syntax
//    - support valuename=-  delete registry value syntax
//    - make it easier to specify quotes in string format
//      introduce 'string:' format specifier, which does not need delimiting quotes.
//    - fix sz and multisz decoding, to properly convert from utf16 -> utf8


enum RegAction {
    DO_LOAD,
    DO_LIST,
    DO_DELETE,
#ifndef _WIN32_WCE
    DO_SET,
#endif
    DO_CREATE,
};

// 1: do not try to print ascii from binary regblobs
// 2: do not parse registry data at all, always print the raw data.
// 3: hex dump of keys too.
int g_outputHex= 0;

int g_maxDepth= -1;
bool g_doFlushkeys= false;


#ifdef WINCEREGUTL
bool ITRegistryFlush()
{
    DWORD outsize=0;
    BYTE *outbuf=NULL;

    HRESULT res= ItsutilsInvoke("ITRegistryFlush",
            0, NULL, &outsize, (BYTE**)&outbuf);
    if (outbuf!=NULL)
        RapiFree(outbuf);

    return res==0;
}
#endif



bool IsValueNameSpec(const std::string& spec)
{
    if (spec[0]!=':')
        return false;
    if (spec.find('=')==std::string::npos)
        return true;

    if (spec[1]=='\'' || spec[1]=='\"')
    {
        size_t endquote= findendquote(spec, 2, spec[1]);

        if (endquote==std::string::npos)
        {
            throw stringformat("IsValueNameSpec: missing endquote in '%hs'", spec.c_str());
        }
        return endquote==spec.size();
    }
    return false;
}


std::string GetNameFromValueNameSpec(const std::string& spec, size_t start)
{
    if (spec[start]=='\'' || spec[start]=='\"')
    {
        size_t endquote= findendquote(spec, start+1, spec[start]);
        //debug("GetNameFromValueNameSpec:%s\n", spec.substr(1, endquote-3).c_str());
        return cstrunescape(spec.substr(start, endquote-start-1));
    }
    //debug("GetNameFromValueNameSpec:%s\n", spec.substr(1).c_str());
    return spec.substr(start);
}


bool IsRegFile(const std::string& filespec)
{
    return filespec[0]=='@';
}
std::string GetFilenameFromRegfileSpec(const std::string& filespec)
{
    return filespec.substr(1);
}

void checkparameters(RegAction action, const RegistryKey::List& keys, const StringList& names, const RegistryValue::StringMap& values)
{
    if (action==DO_CREATE && names.size())
        throw std::string("checkparameters: create with name");
    if (action==DO_CREATE && values.size())
        throw std::string("checkparameters: create with 'name=value'");
    if (action==DO_CREATE && keys.size()==0)
        throw std::string("checkparameters: create without keys");
    if (action==DO_DELETE && values.size())
        throw std::string("checkparameters: delete with 'name=value'");
    if (action==DO_DELETE && keys.size()==0)
        throw std::string("checkparameters: delete without keys");
    if (action==DO_LIST && values.size())
        throw std::string("checkparameters: list with 'name=value'");
    if (action==DO_LIST && keys.size()==0)
        throw std::string("checkparameters: list without keys");
#ifndef _WIN32_WCE
    if (action==DO_SET && names.size())
        throw std::string("checkparameters: set value with bare name");
    if (action==DO_SET && values.size()==0)
        throw std::string("checkparameters: set without values");
#endif
}


#ifdef _WIN32_WCE
int WINAPI WinMain( HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   LPTSTR    lpCmdLine,
                   int       nCmdShow)
{
//    DebugOutputDebugString();
    DebugSetLogfile("regbk.log");
    debugt("starting registry dump\n");

    RegAction action= DO_LIST;
    bool fRecurse= false;

    RegistryKey::List keys;
    StringList names;
    RegistryValue::StringMap values;
    StringList regfiles;

    StringList args;
    if (!SplitString(ToString(lpCmdLine), args, false))
    {
        error("Error in commandline");
        return false;
    }
    StringList keylist;
    g_outputHex= 1;
    for (StringList::iterator i= args.begin() ; i!=args.end() ; ++i)
    {
        std::string& arg= *i;
        if (arg[0]=='-') switch(arg[1])
        {
            case 'X': g_outputHex= 0; break;
        }
        else {
            keylist.push_back(arg);
        }
    }

    if (keylist.size()==0 || tolower(keylist[0])=="install") {
        if (keylist.size())
            DebugSetLogfile("\\SD Card\\regbk.log");
        RegistryKey::FromKeySpec("HKCU").DumpKey(g_outputHex, g_maxDepth);
        RegistryKey::FromKeySpec("HKLM").DumpKey(g_outputHex, g_maxDepth);
        RegistryKey::FromKeySpec("HKCR").DumpKey(g_outputHex, g_maxDepth);
    }
    else {
        for (int i=0 ; i<keylist.size() ; i++)
            RegistryKey::FromKeySpec(keylist[i]).DumpKey(g_outputHex, g_maxDepth);
    }

    debugt("finished registry dump\n");

    MessageBeep(MB_OK);
    return 0;
}
#else
void usage()
{
    printf("(C) 2003-2008 Willem jan Hengeveld  itsme@xs4all.nl\n");
    debug("Usage: pregutl [keys] [values] [@regfile]\n");
    debug("  -d   delete value or key\n");
    debug("  -c   create key\n");
    debug("  -s   set value\n");
    debug("  -Rmaxdepth   specify max recursion depth\n");
    debug("  -x   output hex values as full hexdump. instead of trying to print ascii\n");
    debug("  -xx  output all values as hex\n");
    debug("  -f   flush registry changes to disk\n");
    debug("\n");
    debug("key-values are specified as follows:\n");
    debug("    :valuename  or :'value name'\n");
    debug("    :valuename=value\n");
    debug("use an empty string for the default value\n");
    debug("\n");
    debug("values are specified as follows:\n");
    debug("    dword:01234567  or \"str\\n\\\"str\" or\n");
    debug("    multi_sz:\"...\",\"...\" or  hex:ff,11,22\n");
    debug("    note that you may also use single (') quotes instead\n");
    debug("    note also, that backslashes in strings must be escaped: \"\\\\windows\"\n");
    debug("    otherwise it would be almost impossible to enter quotes on the dos cmdline\n");
    debug("\n");
    debug("    strings may also be specified unquoted, with a 'string:' prefix\n");
    debug("    dword values may also be specified as 'dec:1234' or 'bitmask:1010101'\n");
    debug("\n");
    debug("    use 'file(<type>):filename' to read the value from <filename>\n");
    debug("\n");
    debug("    with hex() and file() a value type may be specified, either as a decimal nr\n");
    debug("    or as a typename: none, sz, binary, dword, ... etc\n");
    debug("\n");
    debug("keys are specified as follows:\n");
    debug("    HKLM\\Software\\HTC\n");
    debug("\n");
    debug("if multiple keys and keyvals are specified pregutl\n");
    debug("operates on all combinations\n");
}

int main(int argc, char *argv[])
{
    DebugStdOut();

    RegAction action= DO_LIST;

    RegistryKey::List keys;
    StringList names;
    RegistryValue::StringMap values;
    StringList regfiles;

    try {
    for (int i=1 ; i<argc ; i++)
    {
        if (argv[i][0]=='-') switch(argv[i][1])
        {
            case 'd': action= DO_DELETE; break;
            case 'c': action= DO_CREATE; break;
            case 's': action= DO_SET; break;
            case 'f': g_doFlushkeys= true; break;
            case 'R': g_maxDepth= strtoul(argv[i]+2,0,0); break;
            case 'x': 
                      if (g_outputHex==1 || argv[i][2]=='x') {
                          if (g_outputHex==2 || argv[i][3]=='x') {
                              g_outputHex= 3;
                          }
                          else {
                              g_outputHex= 2;
                          }
                      }
                      else {
                          g_outputHex= 1;
                      }
                      break;
            default:
                usage();
                return 1;
        }
        else if (IsValueNameSpec(argv[i]))
        {
            names.push_back(GetNameFromValueNameSpec(argv[i], 1));
        }
        else if (IsSetSpec(argv[i]))
        {
            values[GetNameFromSetSpec(argv[i], 1)]= RegistryValue::FromValueSpec(GetValueSpecFromSetSpec(argv[i], 1));
        }
        else if (IsRegFile(argv[i]))
        {
            regfiles.push_back(GetFilenameFromRegfileSpec(argv[i]));
        }
        else
            keys.push_back(RegistryKey::FromKeySpec(std::string(argv[i])));
    }
    }
    catch(std::string &e) {
        debug("ERROR: %s\n", e.c_str());
        return 1;
    }
    if (!regfiles.empty())
        action= DO_LOAD;

    try {
        checkparameters(action, keys, names, values);
    }
    catch(std::string &e) {
        debug("ERROR: %s\n", e.c_str());
        return 1;
    }


#ifdef WINCEREGUTL
    if (g_doFlushkeys)
        CheckITSDll();
    else if (FAILED(CeRapiInit()))
    {
        debug( "Failed to init rapi\n");
        return 1;
    }
#endif

    try {
    for (RegistryKey::List::iterator i= keys.begin() ; i!=keys.end() ; ++i)
    {
        switch(action)
        {
        case DO_CREATE:
            try {
                (*i).CreateKey();
            } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
            break;
        case DO_DELETE:
            if (names.size())
                for (StringList::iterator j= names.begin() ; j!=names.end() ; ++j)
                    try {
                        (*i).DeleteValue(*j);
                    } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
            else
                try {
                    (*i).DeleteKey();
                } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
            break;
        case DO_LIST:
            try {
                (*i).DumpKey(g_outputHex, g_maxDepth);
            } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
            break;
        case DO_SET:
            for (RegistryValue::StringMap::iterator j= values.begin() ; j!=values.end() ; ++j)
                try {
                    (*i).SetValue((*j).first, (*j).second);
                } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
            break;
        case DO_LOAD:
            debug("ERROR: not expecting load here\n");
            break;
        }
    }
    struct win32maker : regkeymaker {
        RegistryKey curkey;
        void newkey(const RegistryPath& path)
        {
            curkey= RegistryKey(path);
            curkey.CreateKey();
        }
        void setval(const std::string& name, const RegistryValue& value)
        {
            curkey.SetValue(name, value);
        }
    };
    win32maker mk;
    for (StringList::iterator i= regfiles.begin() ; i!=regfiles.end() ; ++i)
    {
        try {
            ProcessRegFile(*i, mk);
        } catch(std::string &e) { debug("WARNING: %s\n", e.c_str()); }
    }
    } catch(std::string &e) { debug("ERROR: %s\n", e.c_str()); return 1; }

#ifdef WINCEREGUTL
    if (g_doFlushkeys)
        ITRegistryFlush();

    StopItsutils();
#endif

    return 0;
}
#endif


