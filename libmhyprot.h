#pragma once

#include <Windows.h>

//
// needed to prepare binary from memory to disk
//
#include <fstream>


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
		uint64_t address,
		void* buffer,
		size_t size
	);

	//
	// template definition of reading kernel memory above
	//
	template<class T> T read_kernel_memory(uint64_t address)
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
	extern bool read_user_memory_raw(
		const uint32_t process_id,
		uint64_t address,
		void* buffer,
		size_t size
	);

	//
	// template definition of reading user memory above
	//
	template<class T> T read_user_memory(
		const uint32_t process_id, uint64_t address
	)
	{
		T buffer;
		read_user_memory_raw(process_id, address, &buffer, sizeof(T));
		return buffer;
	}

	//
	// write any memory to the process by specific process id
	// without process handle which granted permission by system
	// privilege level: kernel (ring-0)
	//
	extern bool write_user_memory_raw(
		const uint32_t process_id,
		uint64_t address,
		void* buffer,
		size_t size
	);

	//
	// template definition of writing user memory above
	//
	template<class T> bool write_user_memory(
		const uint32_t process_id, uint64_t address, T value
	)
	{
		return write_user_memory_raw(process_id, address, &value, sizeof(T));
	}
}