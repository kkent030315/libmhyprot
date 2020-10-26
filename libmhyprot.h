/*
 * MIT License
 *
 * Copyright (c) 2020 Kento Oki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#pragma once

#include <Windows.h>

//
// needed to prepare binary from memory to disk
//
#include <fstream>
#include <vector>


//
// +---------------------------------------------------------------------------+
// |                                                                           |
// |                               libmhyprot                                  |
// |      A wrapper for the vulnerable driver to execute mhyprot exploits      |
// |                                                                           |
// +---------------------------------------------------------------------------+
// |                                                                           |
// | what it does:                                                             |
// |      the binary of mhyprot.sys will be loaded our memory to disk.         |
// |      please note that there is an possibility that the driver will remain |
// |      on your system if you did not unload the library properly, or        |
// |      somethings fails on the our processes.                               |
// |                                                                           |
// +---------------------------------------------------------------------------+
//

typedef struct _MHYPROT_THREAD_INFORMATION
{
	uint64_t kernel_address;
	uint64_t start_address;
	bool unknown;
} MHYPROT_THREAD_INFORMATION, * PMHYPROT_THREAD_INFORMATION;

namespace libmhyprot
{

	//
	// initialization of this library
	//
	extern bool mhyprot_init();

	//
	// uninitialization of this library
	// note: if you did not call this, the driver will remains on your system.
	//
	extern void mhyprot_unload();

	//
	// read any memory on the kernel
	// privilege level: kernel (ring-0)
	//
	extern bool read_kernel_memory(
		const uint64_t& address, void* buffer, const size_t& size
	);

	//
	// template definition of reading kernel memory above
	//
	template<class T> T read_kernel_memory(const uint64_t& address)
	{
		T buffer;
		read_kernel_memory(address, &buffer, sizeof(T));
		return buffer;
	}

	//
	// read any process memory by specific process id
	// without process handle which granted permission by system
	// privilege level: kernel (ring-0)
	//
	extern bool read_process_memory(
		const uint32_t& process_id,
		const uint64_t& address, void* buffer, const size_t& size
	);

	//
	// template definition of reading user memory above
	//
	template<class T> T read_process_memory(
		const uint32_t& process_id, const uint64_t& address
	)
	{
		T buffer;
		read_process_memory(process_id, address, &buffer, sizeof(T));
		return buffer;
	}

	//
	// write any memory to the process by specific process id
	// without process handle which granted permission by system
	// privilege level: kernel (ring-0)
	//
	extern bool write_process_memory(
		const uint32_t& process_id,
		const uint64_t& address, void* buffer, const size_t& size
	);

	//
	// template definition of writing user memory above
	//
	template<class T> bool write_process_memory(
		const uint32_t& process_id,
		const uint64_t& address, const T& value
	)
	{
		return write_process_memory(process_id, address, (void*)&value, sizeof(T));
	}

	//
	// get a number of modules that loaded in the target process
	//
	extern bool get_process_modules(
		const uint32_t& process_id, const uint32_t max_count,
		std::vector< std::pair<std::wstring, std::wstring> >& result
	);

	//
	// get all of threads that registered in the target process
	// kernel_address is a pointer to the _ETHREAD object in kernel
	//
	extern bool get_process_threads(
		const uint32_t& process_id, const uint32_t& owner_process_id,
		std::vector<MHYPROT_THREAD_INFORMATION>& result
	);

	//
	// get a system uptime by seconds
	//
	extern uint32_t get_system_uptime();

	//
	// terminate specific process by process id
	// this eventually calls ZwTerminateProcess in the driver context
	//
	extern bool terminate_process(const uint32_t process_id);
}