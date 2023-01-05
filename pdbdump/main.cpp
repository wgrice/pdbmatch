#include "Windows.h"

#include <iomanip>
#include <iostream>
#include <tchar.h>

#include "msf/file_stream.h"
#include "msf/msf.h"
#include "msf/stream.h"
#include "pdb/format.h"
#include "pdb/pdb.h"


LPCTSTR ProcessCmdLine(int argc, TCHAR* argv[])
{
    if (argc < 2)
    {
        _tprintf(_T("Usage: %s FileName \n"), argv[0]);
        return 0;
    }

    return argv[1];
}

void printGUID(uint8_t guid[16], std::ostream& os) {
    const auto flags = os.flags();

    os << std::hex << std::setfill('0') << std::setw(2) << std::uppercase;

    for (size_t i = 0; i < 4; ++i) os << (int)guid[i];
    os << "-";
    for (size_t i = 4; i < 6; ++i) os << (int)guid[i];
    os << "-";
    for (size_t i = 6; i < 8; ++i) os << (int)guid[i];
    os << "-";
    for (size_t i = 8; i < 10; ++i) os << (int)guid[i];
    os << "-";
    for (size_t i = 10; i < 16; ++i) os << (int)guid[i];

    // Restore flags
    os.flags(flags);
}

/**
 * Prints a nicely formatted page sequences (as if you were specifying the pages
 * to be printed).
 *
 * For example, the page list:
 *
 *    [0, 1, 2, 3, 4, 6, 7, 8, 9, 20]
 *
 * is printed as
 *
 *    [0-4, 6-9, 20]
 */
void printPageSequences(const std::vector<uint32_t>& pages, std::ostream& os) {
    os << "[";

    for (size_t i = 0; i < pages.size();) {
        if (i > 0) os << ", ";

        uint32_t start = pages[i];
        uint32_t count = 0;

        ++i;

        // Find how long a run of pages is.
        for (; i < pages.size() && pages[i] == pages[i - 1] + 1; ++i) ++count;

        if (count == 0) {
            os << start << " (0x" << std::hex << (uint64_t)start * 4096 << "-0x"
                << ((uint64_t)start + 1) * 4096 - 1 << ")" << std::dec;
        }
        else {
            os << start << "-" << start + count << " (0x" << std::hex
                << ((uint64_t)start) * 4096 << "-0x"
                << ((uint64_t)start + count + 1) * 4096 - 1 << ")" << std::dec;
        }
    }

    os << "]";
}

int printStreamPages(MsfStreamRef stream, std::ostream& os)
{
    auto fileStream = std::dynamic_pointer_cast<MsfFileStream>(stream);
    const auto& pages = fileStream->pages();

    os << "Stream Pages: " << pages.size() << " pages ";

    printPageSequences(pages, os);

    std::cout << std::endl;

    if (pages.size() == 0)
        return 0;
    else
        return pages[0] * 4096;
}

void printPdbStream(MsfFile& msf, std::ostream& os) {
    static const size_t streamid = (size_t)PdbStreamType::header;

    auto stream = msf.getStream(streamid);
    if (!stream)
    {
        os << ("Error: missing PDB header stream") << std::endl;
        return;
    }

    os << "PDB Stream Info\n"
        << "===============\n";

    os << "Stream ID:   " << streamid << std::endl;
    os << "Stream Size: " << stream->length() << " bytes" << std::endl;
    int pagePos = printStreamPages(stream, os);
	os << std::endl;

    PdbStream70 header;
    if (stream->read(sizeof(header), &header) != sizeof(header))
    {
        os << ("Error: missing PDB 7.0 header") << std::endl;
        return;
    }

    os << "Header\n"
        << "------\n";
    os << "Version:   " << (uint32_t)header.version << std::endl;
    os << "Timestamp: " << header.timestamp << std::endl;
    os << "Age:       " << header.age << "[0x" << std::hex << pagePos + (long long)&header.age - (long long)&header << std::dec << "+" << sizeof(header.age) << "]" << std::endl;
    os << "Signature: ";
    printGUID(header.sig70, os);
    os << "[0x" << std::hex << pagePos + (long long)&header.sig70 - (long long)&header << std::dec << "+" << sizeof(header.sig70) << "]" << std::endl;
    os << std::endl;
}

void printDbiStream(MsfFile& msf, std::ostream& os) {
    static const size_t streamid = (size_t)PdbStreamType::dbi;

    auto stream = msf.getStream(streamid);
    if (!stream) return;

    os << "DBI Stream Info\n"
        << "===============\n";
    os << "Stream ID:   " << streamid << std::endl;
    os << "Stream Size: " << stream->length() << " bytes" << std::endl;
    int pagePos = printStreamPages(stream, os);
	os << std::endl;

    DbiHeader dbi;
    if (stream->read(sizeof(dbi), &dbi) != sizeof(dbi))
    {
        os << ("Error: missing DBI dbi") << std::endl;
        return;
    }

    os << "Header\n"
        << "------\n";
    os << "Signature:                          0x" << std::hex << dbi.signature
        << std::dec << std::endl
        << "Version:                            " << (uint32_t)dbi.version
        << std::endl
        << "Age:                                " << dbi.age << "[0x" << std::hex << pagePos + (long long)&dbi.age - (long long)&dbi << std::dec << "+" << sizeof(dbi.age) << "]"
		<< std::endl
        << "Global Symbol Info (GSI) Stream ID: " << dbi.globalSymbolStream
        << std::endl
        << "PDB DLL Version:                    " << dbi.pdbDllVersion.major
        << "." << dbi.pdbDllVersion.minor << "." << dbi.pdbDllVersion.format
        << std::endl
        << "Public Symbol Info (PSI) Stream ID: " << dbi.publicSymbolStream
        << std::endl
        << "PDB DLL Build Major Version:        " << dbi.pdbDllBuildVersionMajor
        << std::endl
        << "Symbol Records Stream ID:           " << dbi.symbolRecordsStream
        << std::endl
        << "PDB DLL Build Minor Version:        " << dbi.pdbDllBuildVersionMinor
        << std::endl
        << "Module Info Size:                   " << dbi.gpModInfoSize
        << " bytes" << std::endl
        << "Section Contribution Size:          " << dbi.sectionContributionSize
        << " bytes" << std::endl
        << "Section Map Size:                   " << dbi.sectionMapSize
        << " bytes" << std::endl
        << "File Info Size:                     " << dbi.fileInfoSize << " bytes"
        << std::endl
        << "Type Server Map Size:               " << dbi.typeServerMapSize
        << " bytes" << std::endl
        << "MFC Type Server Index:              " << dbi.mfcIndex << std::endl
        << "Debug Header Size:                  " << dbi.debugHeaderSize
        << " bytes" << std::endl
        << "EC Info Size:                       " << dbi.ecInfoSize << " bytes"
        << std::endl
        << "Flags:" << std::endl
        << "    Incrementally Linked:           "
        << (dbi.flags.incLink ? "yes" : "no") << std::endl
        << "    Stripped:                       "
        << (dbi.flags.stripped ? "yes" : "no") << std::endl
        << "    CTypes:                         "
        << (dbi.flags.ctypes ? "yes" : "no") << std::endl
        << "Machine Type:                       " << dbi.machine << std::endl
        << std::endl;
}

void dumpPdb(MsfFile& msf) {
    printPdbStream(msf, std::cout);
    printDbiStream(msf, std::cout);
}

int _tmain(int argc, TCHAR* argv[])
{
    LPCTSTR FileName = ProcessCmdLine(argc, argv);
    if (FileName == 0)
        return 1;
    _tprintf(_T("File: %s \n\n"), FileName);

    try {
        const auto pdb = openFile(FileName, FileMode<TCHAR>::readExisting);
        MsfFile msf(pdb);
        dumpPdb(msf);
    }
    catch (const std::system_error& error) {
        std::cerr << "Error: " << error.what() << "\n";
        return 1;
    }
    return 0;
}
