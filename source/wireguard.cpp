// wireguard.cpp
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

namespace wg
{
	namespace stdfs = std::filesystem;
	zst::Failable<int> interface_up_impl(const Config& config);
	zst::Failable<int> interface_down_impl(const Config& config);

	Result<zprocpipe::Process, int>
	run_cmd(const std::string& cmd, const std::vector<std::string>& args, bool quiet, bool change_pgid)
	{
		if(is_verbose() && not quiet)
		{
			std::string p = cmd;
			for(auto& a : args)
				p += " ", p += a;

			msg::log3("{}", p);
		}

		auto [maybe_proc, err] = zprocpipe::runProcess(cmd, args, quiet, quiet, change_pgid);
		if(not maybe_proc.has_value())
			return msg::error("Failed to launch {}{}: {}", cmd, args, err);

		if(auto code = maybe_proc->wait(); code != 0)
			return msg::error("Command {}{} failed with exit code {}\n", cmd, args, code);

		return Ok(std::move(*maybe_proc));
	}

	zst::Failable<int> set_wireguard_config(const Config& config, const std::string& interface_name)
	{
		// set the config
		auto fifo_path = stdfs::temp_directory_path() / zpr::sprint("tmp-{}.conf", config.name);

		auto wg_conf = config.to_wg_conf();
		auto fifo_fd = open(fifo_path.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if(fifo_fd < 0)
			return msg::error("Failed to open config fifo: {} ({})", strerror(errno), errno);

		// unlink the guy so it doesn't show up in the filesystem
		stdfs::remove(fifo_path);
		TRY(util::write_to_file(fifo_fd, wg_conf));

		msg::log("Configuring WireGuard");
		TRY(run_cmd("wg", { "setconf", interface_name, zpr::sprint("/dev/fd/{}", fifo_fd) }));
		close(fifo_fd);

		return Ok();
	}


	zst::Failable<int> restart(const Config& config)
	{
		if(pid_t child = fork(); child < 0)
			return msg::error("fork(): %s (%d)", strerror(errno), errno);
		else if(child != 0)
			_exit(0);

		// we are the child now
		if(setsid() < 0)
			return msg::error("setsid(): %s (%d)", strerror(errno), errno);

		// to prevent leaving the thing in a down state if possible, ignore errors on down.
		(void) wg::down(config);

		TRY(wg::up(config));
		return Ok();
	}

	static zst::Result<std::string, int> write_wgquick_conf(const Config& config)
	{
		auto wgq_conf = config.to_wg_quick_conf();
		auto conf_path = stdfs::temp_directory_path() / zpr::sprint("{}.conf", config.name);

		int fd = open(conf_path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
		if(fd < 0)
			return msg::error("Could not create {}: {} ({})", conf_path.string(), strerror(errno), errno);

		// unlink the guy so it doesn't show up in the filesystem
		TRY(util::write_to_file(fd, wgq_conf));
		close(fd);

		return Ok(conf_path.string());
	}

	zst::Failable<int> up(const Config& config)
	{
		if(config.use_wg_quick)
		{
			if(does_interface_exist(config.name))
				return msg::error("Interface '{}' already exists", config.name);

			msg::log("Creating interface {}", config.name);
			msg::log2("Invoking wg-quick");

			auto conf_path = TRY(write_wgquick_conf(config));

			TRY(run_cmd("wg-quick", { "up", conf_path }, /* quiet: */ not is_verbose(), /* change_pgid: */ false));
			stdfs::remove(conf_path);

#if defined(__APPLE__)
			// check what is the real interface on macos
			auto real_iface = TRY(macos_get_real_interface(config.name));
			msg::log2("Tunnel interface: {}", real_iface);
#endif

			msg::log("Done!");
			return Ok();
		}
		else
		{
#if defined(__APPLE__)
			msg::error("wgman on macOS can only use wg-quick!");
			msg::log2("set `use-wg-quick = true` in the config");
			return Err(0);
#endif
			return interface_up_impl(config);
		}
	}

	zst::Failable<int> down(const Config& config)
	{
		if(config.use_wg_quick)
		{
			if(not does_interface_exist(config.name))
				return msg::error("Interface '{}' does not exist", config.name);

			msg::log("Removing interface {}", config.name);
			msg::log2("Invoking wg-quick");

			auto conf_path = TRY(write_wgquick_conf(config));

			TRY(run_cmd("wg-quick", { "down", conf_path }, /* quiet: */ not is_verbose(), /* change_pgid: */ false));
			stdfs::remove(conf_path);

			msg::log("Done!");
			return Ok();
		}
		else
		{
#if defined(__APPLE__)
			msg::error("wgman on macOS can only use wg-quick!");
			msg::log2("set `use-wg-quick = true` in the config");
			return Err(0);
#endif
			return interface_down_impl(config);
		}
	}
}
