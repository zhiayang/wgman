// wireguard_common.h
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "wgman.h"
#include "zprocpipe.h"

namespace wg
{
	zst::Result<zprocpipe::Process, int>
	run_cmd(const std::string& cmd, const std::vector<std::string>& args, bool quiet = false, bool change_pgid = true);

	zst::Failable<int> set_wireguard_config(const Config& config, const std::string& interface_name);

	bool does_interface_exist(const std::string& name);
	Result<std::string, int> macos_get_real_interface(const std::string& wg_iface, bool quiet = false);
}
