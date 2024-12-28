#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <Softpub.h>
#include <wintrust.h>

#pragma comment (lib, "wintrust")

namespace fs = std::filesystem;

BOOL VerifyEmbeddedSignature(const fs::path& file)
{
    WINTRUST_FILE_INFO fileData{};
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = file.c_str();
    fileData.hFile = nullptr;
    fileData.pgKnownSubject = nullptr;

    GUID wVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData{};

    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = nullptr;
    winTrustData.pSIPClientData = nullptr;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.hWVTStateData = nullptr;
    winTrustData.pwszURLReference = nullptr;
    winTrustData.dwUIContext = 0;
    winTrustData.pFile = &fileData;

    const LONG lStatus{
        WinVerifyTrust(
            nullptr,
            &wVTPolicyGUID,
            &winTrustData)
    };

    // Any hWVTStateData must be released by a call with close.
    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

    return lStatus == ERROR_SUCCESS;
}

bool readBytes(std::ifstream& file, void* buffer, const std::size_t& size)
{
    if (!file.read(static_cast<char*>(buffer), size))
    {
        return false;
    }
    return true;
}

void parseDll(const fs::path& dllPath)
{
    std::ifstream file(dllPath, std::ios::binary);
    if (!file.is_open())
    {
        //std::cerr << "Failed to open " << dllPath << "\n";
        return;
    }

    // Read DOS header
    IMAGE_DOS_HEADER dosHeader{};
    if (!readBytes(file, &dosHeader, sizeof(dosHeader)))
    {
        //std::cerr << "Failed to read DOS header for " << dllPath << "\n";
        return;
    }

    // Check DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        // std::cerr << dllPath << " is not a valid PE file (DOS signature mismatch)\n";
        return;
    }

    // Move file pointer to NT headers offset
    file.seekg(dosHeader.e_lfanew, std::ios::beg);

    // Read NT headers (Signature + IMAGE_FILE_HEADER + optional header)
    DWORD ntSignature{0};
    if (!readBytes(file, &ntSignature, sizeof(ntSignature)) ||
        ntSignature != IMAGE_NT_SIGNATURE)
    {
        // std::cerr << "NT signature mismatch in " << dllPath << "\n";
        return;
    }

    IMAGE_FILE_HEADER fileHeader{};
    if (!readBytes(file, &fileHeader, sizeof(fileHeader)))
    {
        // std::cerr << "Failed to read IMAGE_FILE_HEADER for " << dllPath << "\n";
        return;
    }

    IMAGE_OPTIONAL_HEADER32 optionalHeader32{};
    IMAGE_OPTIONAL_HEADER64 optionalHeader64{};
    bool isPE32Plus{false};

    // Peek the Magic field first
    std::streampos optionalHeaderPos{file.tellg()};
    WORD magic;
    if (!readBytes(file, &magic, sizeof(magic)))
    {
        //std::cerr << "Failed to peek optional header magic for " << dllPath << "\n";
        return;
    }

    file.seekg(optionalHeaderPos, std::ios::beg);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        // 64-bit
        isPE32Plus = true;
        if (!readBytes(file, &optionalHeader64, sizeof(optionalHeader64)))
        {
            //std::cerr << "Failed to read IMAGE_OPTIONAL_HEADER64 for " << dllPath << "\n";
            return;
        }
    }
    else
    {
        // 32-bit
        if (!readBytes(file, &optionalHeader32, sizeof(optionalHeader32)))
        {
            //std::cerr << "Failed to read IMAGE_OPTIONAL_HEADER32 for " << dllPath << "\n";
            return;
        }
    }

    // Number of sections = fileHeader.NumberOfSections
    // Move to first section header
    // The section headers immediately follow the optional header
    // e_lfanew + 4 (NT signature) + sizeof(IMAGE_FILE_HEADER) + SizeOfOptionalHeader
    const WORD numberOfSections = fileHeader.NumberOfSections;

    // In practice, you'd want to check that the numberOfSections is reasonable
    // and that the file is large enough.

    std::vector<IMAGE_SECTION_HEADER> sectionHeaders(numberOfSections);
    for (WORD i{0}; i < numberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER section{};
        if (!readBytes(file, &section, sizeof(section)))
        {
            // std::cerr << "Failed to read section header " << i << " for " << dllPath << "\n";
            return;
        }
        sectionHeaders[i] = section;
    }

    for (WORD i{0}; i < numberOfSections; ++i)
    {
        auto& s{sectionHeaders[i]};

        char name[9];
        std::memcpy(name, s.Name, sizeof(name) - 1);
        name[8] = '\0';

        const bool canRead = (s.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        const bool canWrite = (s.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        const bool canExecute = (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

        if (canRead && canWrite && canExecute)
        {
            if (VerifyEmbeddedSignature(dllPath))
            {
                std::cout << "=== " << dllPath.string() << " ===\n";
                std::cout << "Signed by a trusted source\n";
                std::cout << "Machine: 0x"
                    << std::hex << fileHeader.Machine << std::dec
                    << (isPE32Plus ? " (64-bit)\n" : " (32-bit)\n");
                std::cout << "Sections: " << numberOfSections << "\n";

                std::cout << "  Section " << i << ": "
                    << name << "\n";
                std::cout << "    VirtualSize:  0x"
                    << std::hex << s.Misc.VirtualSize << std::dec << "\n";
                std::cout << "    VirtualAddr:  0x"
                    << std::hex << s.VirtualAddress << std::dec << "\n";
                std::cout << "    RawSize:      0x"
                    << std::hex << s.SizeOfRawData << std::dec << "\n";
                std::cout << "    Characteristics: 0x"
                    << std::hex << s.Characteristics << std::dec << "\n";

                std::cout << "    Permissions: [ "
                    << (canRead ? "R " : "")
                    << (canWrite ? "W " : "")
                    << (canExecute ? "X " : "")
                    << "]\n\n";
            }
        }
    }
}

void ListFilesRecursive(const std::wstring& folder)
{
    const std::wstring pattern{folder + L"\\*"};

    WIN32_FIND_DATAW findData{};
    const HANDLE hFind{FindFirstFileW(pattern.c_str(), &findData)};
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return;
    }

    do
    {
        const std::wstring fileOrDirName{findData.cFileName};

        if (fileOrDirName == L"." || fileOrDirName == L"..")
        {
            continue;
        }

        const std::wstring fullPath{folder + L"\\" + fileOrDirName};

        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ListFilesRecursive(fullPath);
        }
        else
        {
            if (fullPath.size() >= 4)
            {
                const std::wstring ext{fullPath.substr(fullPath.size() - 4)};
                if (_wcsicmp(ext.c_str(), L".dll") == 0)
                {
                    parseDll(fullPath);
                }
            }
        }
    }
    while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);
}

int wmain(const int argc, const wchar_t* const argv[])
{
    if (argc < 2)
    {
        std::wcerr << "Usage: " << argv[0]
            << " <directory containing .dll files>\n";
        return 1;
    }

    const fs::path targetDir{argv[1]};
    if (!exists(targetDir) || !is_directory(targetDir))
    {
        std::cerr << "Invalid directory: " << targetDir << "\n";
        return 1;
    }

    ListFilesRecursive(targetDir);

    return 0;
}
