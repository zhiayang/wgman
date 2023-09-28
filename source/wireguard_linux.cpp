// wireguard_linux.cpp
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

// only for linux
#if defined(__linux__)

namespace wg
{
	namespace stdfs = std::filesystem;

	bool does_interface_exist(const std::string& name)
	{
		auto [_, code] = util::try_command("ip", { "link", "show", "dev", name });
		return code == 0;
	}

	zst::Failable<int> interface_up_impl(const Config& config)
	{
		if(does_interface_exist(config.name))
			return msg::error("Interface '{}' already exists", config.name);

		msg::log("Creating interface {}", config.name);
		TRY(run_cmd("ip", { "link", "add", config.name, "type", "wireguard" }));
		auto kill_interface = util::defer([&config]() { run_cmd("ip", { "link", "delete", "dev", config.name }); });

		// on linux, the interface name is the wireguard config name.
		TRY(set_wireguard_config(config, config.name));
		kill_interface.disarm();

		msg::log("IP setup");
		TRY(run_cmd("ip", { "-4", "address", "add", config.subnet, "dev", config.name }));

		if(config.mtu.has_value())
		{
			msg::log2("Setting MTU to {} and bringing up device", *config.mtu);
			TRY(run_cmd("ip", { "link", "set", "mtu", zpr::sprint("{}", *config.mtu), "up", "dev", config.name }));
		}
		else
		{
			msg::log("Bringing up device");
			TRY(run_cmd("ip", { "link", "set", "dev", config.name, "up" }));
		}

		// check which of the peer AllowedIPs are not covered by this subnet
		for(auto& peer : config.peers)
		{
			auto maybe_add_route = [&config](const std::string& ip) -> zst::Failable<int> {
				if(ip.ends_with("/0"))
				{
					msg::warn("Setting the default route (0.0.0.0/0) is not supported on linux");
					return Ok();
				}

				if(not util::subnet_contains_ip(config.subnet, ip))
					TRY(run_cmd("ip", { "-4", "route", "add", ip, "dev", config.name }));

				return Ok();
			};

			TRY(maybe_add_route(peer.ip));
			for(auto& extra_ip : peer.extra_routes)
				TRY(maybe_add_route(extra_ip));
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

	zst::Failable<int> interface_down_impl(const Config& config)
	{
		if(not does_interface_exist(config.name))
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
#endif
