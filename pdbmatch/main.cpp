#include "Windows.h"

#include <iomanip>
#include <iostream>
#include <tchar.h>

#include "msf/file_stream.h"
#include "msf/msf.h"
#include "msf/stream.h"
#include "pdb/format.h"
#include "pdb/pdb.h"


LPCTSTR usageInfo = _T("PdbMatch - version 1.0\nCopyright(C) 2022 wgrice\n\nUsage:\n\
PdbMatch[-c <PEFile> <PDBFile>]\n        [-m <PEFile> <PDBFile>]\n\n\
- c Check matching between the pe(exe or dll) and pdb file\n\
- m Make the pe(exe or dll) and pdb file match\n\n\
Supported debug information files : PDB 7.0\n");


extern bool DumpPeFile(LPCTSTR filename);
extern bool DumpPdbFile(LPCTSTR filename);
// pe 信息
extern DWORD g_peAge;
extern GUID g_peSig;
// pdb 信息
extern DWORD g_pdbAge;
extern DWORD g_pdbAgeAddr;
extern GUID g_pdbSig;
extern DWORD g_pdbSigAddr;
extern DWORD g_pdbAge2;
extern DWORD g_pdbAge2Addr;

int _tmain(int argc, TCHAR* argv[])
{
    if (argc < 4 || argv[1][0] != '-' || (argv[1][1] != 'c' && argv[1][1] != 'm'))
    {
        _tprintf(usageInfo);
        return -1;
    }

    bool isCheck = argv[1][1] == 'c';

    LPCTSTR pefilename = argv[2];
    LPCTSTR pdbfilename = argv[3];
    if (!DumpPeFile(pefilename) || g_peAge < 0)
        return -1;
    _tprintf(_T("\n\n"));
    if (!DumpPdbFile(pdbfilename)  || g_pdbAge < 0 || g_pdbAge2 < 0) 
        return -1;

    if (isCheck)
    {
	    if (g_peAge == g_pdbAge && g_pdbAge2 == g_pdbAge && 0 == memcmp(&g_peSig, &g_pdbSig, sizeof(GUID)))
	    {
            _tprintf(_T("\n=========== Match ===========\n"));
	    }
        else
        {
            _tprintf(_T("\n=========== Unmatch ===========\n"));
        }
    }
    else
    {
        HANDLE hFile = CreateFile(pdbfilename, GENERIC_WRITE, 0, NULL,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if ((hFile == INVALID_HANDLE_VALUE) || (hFile == NULL))
        {
            _tprintf(_T("Error: Cannot open the pdb file in write mode. Error code: %u \n"), GetLastError());
            return -1;
        }
        bool writeFinished = false;
        do
        {
            DWORD writeBytes = 0;
        	DWORD iRet = 0;
            BOOL bRet = TRUE;
            iRet = SetFilePointer(hFile, (LONG)g_pdbAgeAddr, NULL, FILE_BEGIN);
            if (iRet == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
            {
                break;
            }
            bRet = WriteFile(hFile, &g_peAge, sizeof(DWORD), &writeBytes, NULL);
            if (bRet == FALSE)
            {
                break;
            }
        	SetFilePointer(hFile, (LONG)g_pdbSigAddr, NULL, FILE_BEGIN);
            if (iRet == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
            {
                break;
            }
            bRet = WriteFile(hFile, &g_peSig, sizeof(GUID), &writeBytes, NULL);
            if (bRet == FALSE)
            {
                break;
            }
            SetFilePointer(hFile, (LONG)g_pdbAge2Addr, NULL, FILE_BEGIN);
            if (iRet == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR)
            {
                break;
            }
            bRet = WriteFile(hFile, &g_peAge, sizeof(DWORD), &writeBytes, NULL);
            if (bRet == FALSE)
            {
                break;
            }
            writeFinished = true;
        } while (0);
        CloseHandle(hFile);
        if (writeFinished)
        {
            _tprintf(_T("\n=========== Match[Success] ===========\n"));
        }
        else
        {
            _tprintf(_T("\n=========== Match[Failure] ===========\n"));
        }
    }

    return 0;
}
