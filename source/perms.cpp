// util.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/capability.h>

#include "wgman.h"

namespace wg
{
	static bool have_cap(cap_t caps, cap_value_t cap)
	{
		cap_flag_value_t value;
		if(cap_get_flag(caps, cap, CAP_EFFECTIVE, &value) < 0)
			msg::error_and_exit("Could not check capabilities: {} ({})", strerror(errno), errno);

		return value == CAP_SET;
	}

#define ensure_cap(caps, cap)                           \
	do                                                  \
	{                                                   \
		if(not have_cap((caps), (cap)))                 \
		{                                               \
			msg::warn("Missing capability '{}'", #cap); \
			return perms::NONE;                         \
		}                                               \
	} while(false)


	perms check_perms()
	{
		if(geteuid() == 0)
			return perms::ROOT;

		// get caps
		auto caps = cap_get_proc();
		ensure_cap(caps, CAP_NET_ADMIN);
		ensure_cap(caps, CAP_SETPCAP);

		auto x = CAP_NET_ADMIN;
		if(cap_set_flag(caps, CAP_INHERITABLE, 1, &x, CAP_SET) != 0)
			msg::error_and_exit("Failed to add CAP_NET_ADMIN to inheritable set: {} ({})", strerror(errno), errno);

		if(cap_set_proc(caps) != 0)
			msg::error_and_exit("Failed to set process capabilities: {} ({})", strerror(errno), errno);

		cap_free(caps);
		return perms::CAPABLE;
	}

	void set_ambient_perms()
	{
		if(geteuid() == 0)
			return;

		if(cap_set_ambient(CAP_NET_ADMIN, CAP_SET) != 0)
			msg::error_and_exit("Failed to enable ambient CAP_NET_ADMIN: {} ({})", strerror(errno), errno);
	}

	void reset_ambient_perms()
	{
		if(geteuid() == 0)
			return;

		if(cap_reset_ambient() != 0)
			msg::error_and_exit("Failed to reset ambient capabilities: {} ({})", strerror(errno), errno);
	}
}