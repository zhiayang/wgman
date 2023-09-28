// wireguard_macos.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <filesystem>

#include "wgman.h"
#include "wireguard_common.h"


// this should only be used on macos
#if defined(__APPLE__)

namespace wg
{
	namespace stdfs = std::filesystem;

	constexpr const char* WIREGUARD_DIR = "/var/run/wireguard";

	Result<std::string, int> macos_get_real_interface(const std::string& wg_iface)
	{
		TRY(run_cmd("wg", { "show", "interfaces" }, /* quiet: */ true));
		auto name_path = zpr::sprint("{}/{}.name", WIREGUARD_DIR, wg_iface);
		if(not stdfs::exists(name_path))
			return msg::error("Interface '{}' does not exist", wg_iface);

		auto contents = TRY(util::read_entire_file(name_path));
		auto real_name = util::trim(zst::byte_span(contents.get(), contents.size()).chars());

		auto socket_path = zpr::sprint("{}/{}.sock", WIREGUARD_DIR, real_name);

		// wg-quick does this weird dance, probably to ensure that the interface mapping is not stale
		struct stat st;
		if(stat(name_path.c_str(), &st) < 0)
			return msg::error("stat('{}'): {} ({})", name_path, strerror(errno), errno);

		auto name_mtime = st.st_mtime;
		if(stat(socket_path.c_str(), &st) < 0)
			return msg::error("stat('{}'): {} ({})", socket_path, strerror(errno), errno);

		auto socket_mtime = st.st_mtime;
		if(auto diff = socket_mtime - name_mtime; diff < -2 || diff > 2)
			return msg::error("Interface name/socket out of sync!");

		return Ok(real_name.str());
	}

	bool does_interface_exist(const std::string& iface)
	{
		// refresh the thing
		run_cmd("wg", { "show", "interfaces" }, /* quiet: */ true);
		auto name_path = zpr::sprint("{}/{}.name", WIREGUARD_DIR, iface);
		if(not stdfs::exists(name_path))
			return false;

		// make sure the socket exists as well
		if(macos_get_real_interface(iface).is_err())
			return false;

		return true;
	}

}
#endif
