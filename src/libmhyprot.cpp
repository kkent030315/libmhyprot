#include "libmhyprot.h"
#include "mhyprot.hpp"

#include <iostream>

#define MHYPROT_API_IMPL 

namespace libmhyprot
{
	MHYPROT_API_IMPL bool mhyprot_init()
	{
		if (!mhyprot::init())
		{
			return false;
		}

		if (!mhyprot::driver_impl::driver_init())
		{
			return false;
		}

		return true;
	}

	MHYPROT_API_IMPL void mhyprot_unload()
	{
		mhyprot::unload();
	}

	MHYPROT_API_IMPL bool read_kernel_memory(
		const uint64_t address, void* buffer, const size_t size
	)
	{
		return mhyprot::driver_impl::read_kernel_memory(
			address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool read_user_memory_raw(
		const uint32_t process_id,
		const uint64_t address, void* buffer, const size_t size
	)
	{
		return mhyprot::driver_impl::read_user_memory(
			process_id, address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool write_user_memory_raw(
		const uint32_t process_id,
		const uint64_t address, void* buffer, const size_t size
	)
	{
		return mhyprot::driver_impl::write_user_memory(
			process_id, address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool get_process_modules(
		const uint32_t process_id, const uint32_t max_count,
		std::vector< std::pair<std::wstring, std::wstring> >& result
	)
	{
		return mhyprot::driver_impl::get_process_modules(
			process_id, max_count, result
		);
	}
}