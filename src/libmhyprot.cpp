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
		const uint64_t& address, void* buffer, const size_t& size
	)
	{
		return mhyprot::driver_impl::read_kernel_memory(
			address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool read_process_memory(
		const uint32_t& process_id,
		const uint64_t& address, void* buffer, const size_t& size
	)
	{
		return mhyprot::driver_impl::read_process_memory(
			process_id, address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool write_process_memory(
		const uint32_t& process_id,
		const uint64_t& address, void* buffer, const size_t& size
	)
	{
		return mhyprot::driver_impl::write_process_memory(
			process_id, address, buffer, size
		);
	}

	MHYPROT_API_IMPL bool get_process_modules(
		const uint32_t& process_id, const uint32_t max_count,
		std::vector< std::pair<std::wstring, std::wstring> >& result
	)
	{
		return mhyprot::driver_impl::get_process_modules(
			process_id, max_count, result
		);
	}

	MHYPROT_API_IMPL bool get_process_threads(
		const uint32_t& process_id, const uint32_t& owner_process_id,
		std::vector<MHYPROT_THREAD_INFORMATION>& result
	)
	{
		return mhyprot::driver_impl::get_process_threads(
			process_id, owner_process_id, result
		);
	}

	MHYPROT_API_IMPL uint32_t get_system_uptime()
	{
		return mhyprot::driver_impl::get_system_uptime();
	}

	MHYPROT_API_IMPL bool terminate_process(const uint32_t process_id)
	{
		return mhyprot::driver_impl::terminate_process(process_id);
	}
}