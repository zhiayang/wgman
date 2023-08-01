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
#include "zprocpipe.h"

namespace wg
{
	namespace stdfs = std::filesystem;

	static std::pair<zprocpipe::Process, int> try_command(const std::string& cmd, const std::vector<std::string>& args)
	{
		auto [maybe_proc, err] = zprocpipe::runProcess(cmd, args);
		if(not maybe_proc.has_value())
			msg::error_and_exit("Failed to launch {}{#}: {}", cmd, args, err);

		auto code = maybe_proc->wait();
		return std::make_pair(std::move(*maybe_proc), code);
	}

	static Result<zprocpipe::Process, int> run_cmd(const std::string& cmd, const std::vector<std::string>& args)
	{
		if(is_verbose())
		{
			std::string p = cmd;
			for(auto& a : args)
				p += " ", p += a;

			msg::log3("{}", p);
		}

		auto [maybe_proc, err] = zprocpipe::runProcess(cmd, args);
		if(not maybe_proc.has_value())
			return msg::error("Failed to launch {}{#}: {}", cmd, args, err);

		if(auto code = maybe_proc->wait(); code != 0)
			return msg::error("Command {}{#} failed with exit code {}\n", cmd, args, code);

		return Ok(std::move(*maybe_proc));
	}


	zst::Failable<int> up(const Config& config)
	{
		if(config.use_wg_quick)
		{
			auto wgq_conf = config.to_wg_quick_conf();
			auto path = zpr::sprint("/etc/wireguard/{}.conf", config.name);

			int fd = open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
			if(fd < 0)
				return msg::error("Could not create {}: {} ({})", path, strerror(errno), errno);

			TRY(util::write_to_file(fd, wgq_conf));
			close(fd);

			TRY(run_cmd("wg-quick", { "up", config.name }));
			msg::log("Done!");
			return Ok();
		}

		if(auto [_, code] = try_command("ip", { "link", "show", "dev", config.name }); code == 0)
			return msg::error("Interface '{}' already exists", config.name);

		msg::log("Creating interface {}", config.name);
		TRY(run_cmd("ip", { "link", "add", config.name, "type", "wireguard" }));
		auto kill_interface = util::defer([&config]() { run_cmd("ip", { "link", "delete", "dev", config.name }); });

		// set the config
		auto fifo_path = stdfs::temp_directory_path() / zpr::sprint("tmp-{}.conf", config.name);

		auto wg_conf = config.to_wg_conf();
		auto fifo_fd = open(fifo_path.c_str(), O_WRONLY | O_TRUNC | O_CREAT, 0600);
		if(fifo_fd < 0)
		{
			msg::error("Failed to open config fifo: {} ({})", strerror(errno), errno);
			return Err(0);
		}

		// unlink the guy so it doesn't show up in the filesystem
		stdfs::remove(fifo_path);
		TRY(util::write_to_file(fifo_fd, wg_conf));

		msg::log("Configuring WireGuard");
		TRY(run_cmd("wg", { "setconf", config.name, zpr::sprint("/dev/fd/{}", fifo_fd) }));
		close(fifo_fd);

		kill_interface.disarm();

		// add the routes and stuff
		msg::log("IP setup");
		TRY(run_cmd("ip", { "-4", "address", "add", config.subnet, "dev", config.name }));

		// check which of the peer AllowedIPs are not covered by this subnet
		for(auto& peer : config.peers)
		{
			if(not util::subnet_contains_ip(config.subnet, peer.ip))
				TRY(run_cmd("ip", { "-4", "route", "add", peer.ip, "dev", config.name }));
		}

		if(config.mtu.has_value())
		{
			msg::log2("Setting MTU to {}", *config.mtu);
			TRY(run_cmd("ip", { "link", "set", "mtu", zpr::sprint("{}", *config.mtu), "up", "dev", config.name }));
		}

		if(config.auto_forward || config.auto_masquerade || config.post_up_cmd.has_value())
			msg::log2("Running PostUp hooks");

		if(config.auto_forward)
		{
			auto cmd = zpr::sprint("iptables -I FORWARD 1 -i {} -j ACCEPT", config.name);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		if(config.auto_masquerade)
		{
			assert(config.interface.has_value());

			auto cmd = zpr::sprint("iptables -t nat -I POSTROUTING 1 -o {} -j MASQUERADE", *config.interface);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		if(config.post_up_cmd.has_value())
		{
			auto cmd = util::replace_all(*config.post_up_cmd, "%i", *config.interface);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		msg::log("Done!");
		return Ok();
	}

	zst::Failable<int> down(const Config& config)
	{
		if(config.use_wg_quick)
		{
			TRY(run_cmd("wg-quick", { "down", config.name }));
			msg::log("Done!");
			return Ok();
		}

		if(auto [_, code] = try_command("ip", { "link", "show", "dev", config.name }); code != 0)
			return msg::error("Interface '{}' does not exist", config.name);

		msg::log("Removing interface {}", config.name);
		TRY(run_cmd("ip", { "link", "delete", "dev", config.name }));

		if(config.auto_forward || config.auto_masquerade || config.post_down_cmd.has_value())
			msg::log2("Running PostDown hooks");

		if(config.auto_forward)
		{
			auto cmd = zpr::sprint("iptables -D FORWARD -i {} -j ACCEPT", config.name);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		if(config.auto_masquerade)
		{
			assert(config.interface.has_value());

			auto cmd = zpr::sprint("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", *config.interface);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		if(config.post_down_cmd.has_value())
		{
			auto cmd = util::replace_all(*config.post_down_cmd, "%i", *config.interface);
			TRY(run_cmd("bash", { "-c", cmd }));
		}

		// note: no need to manually delete routes, deleting the interface does that for us.
		msg::log("Done!");
		return Ok();
	}
}