// status.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#include <assert.h>
#include <cstdlib>

#include <chrono>
#include <algorithm>
#include <filesystem>

#include "wgman.h"
#include "zprocpipe.h"
#include "wireguard_common.h"

namespace wg
{
	namespace zpp = zprocpipe;
	namespace stdfs = std::filesystem;

	static std::string time_to_relative_string(int64_t time)
	{
		namespace sc = std::chrono;
		auto diff = sc::duration_cast<sc::seconds>(sc::system_clock::now().time_since_epoch()).count() - time;
		assert(diff >= 0);

		auto [days, r1] = std::div(diff, decltype(diff)(86400));
		auto [hrs, r2] = std::div(r1, decltype(diff)(3600));
		auto [mins, secs] = std::div(r2, decltype(diff)(60));

		if(days > 0)
		{
			if(hrs > 0)
				return zpr::sprint("{}d {}h", days, hrs);
			else
				return zpr::sprint("{}d", days);
		}
		else if(hrs > 0)
		{
			return zpr::sprint("{}h {}m", hrs, mins);
		}
		else if(mins > 0)
		{
			return zpr::sprint("{}m {}s", mins, secs);
		}
		else
		{
			return zpr::sprint("{}s", secs);
		}
	}

	static std::string bytes_to_string(uint64_t n)
	{
		if(n < 1024)
			return zpr::sprint("{}b", n);
		else if(n < 1024ull * 1024ull)
			return zpr::sprint("{.1f}k", static_cast<double>(n) / 1024.0);
		else if(n < 1024ull * 1024ull * 1024ull)
			return zpr::sprint("{.1f}M", static_cast<double>(n) / 1024.0 / 1024.0);
		else if(n < 1024ull * 1024ull * 1024ull * 1024ull)
			return zpr::sprint("{.1f}G", static_cast<double>(n) / 1024.0 / 1024.0 / 1024.0);
		else
			return zpr::sprint("{.1f}T", static_cast<double>(n) / 1024.0 / 1024.0 / 1024.0 / 1024.0);
	}

	static Result<zpp::Process, std::string> wg_show(const std::string& iface)
	{
		set_ambient_perms();
		auto [proc, err] = zpp::runProcess("wg", { "show", iface, "dump" }, /* stdout: */ true, /* stderr: */ false);
		reset_ambient_perms();

		if(not proc.has_value())
			return Err(zpr::sprint("Could not read '{}': {}", iface, std::move(err)));

		return Ok(std::move(*proc));
	}

	void status(const std::string& config_path_, const std::optional<std::string>& interface, bool show_keys)
	{
		auto config_path = stdfs::path(config_path_);

		std::vector<std::string> interfaces;
		if(interface.has_value())
		{
			std::error_code ec {};
			if(not stdfs::exists(config_path / (*interface + ".toml"), ec) && !ec)
				msg::error_and_exit("Interface '{}' does not exist", *interface);
			else if(ec)
				msg::error_and_exit("Could not load config file for interface '{}': {}", *interface, ec.message());

			interfaces.push_back(*interface);
		}
		else
		{
			std::error_code ec {};
			for(auto& dir : stdfs::directory_iterator(config_path, ec))
			{
				auto path = dir.path();
				if(path.extension() == ".toml")
				{
					path.replace_extension("");
					interfaces.push_back(path.filename());
				}
			}

			if(ec)
				msg::error_and_exit("Could not enumerate config files at {}: {}", config_path_, ec.message());
		}

		std::sort(interfaces.begin(), interfaces.end());
		for(auto& wg_iface : interfaces)
		{
			auto config = Config::load(config_path / (wg_iface + ".toml"));
			zpr::print("{}", msg::ALL_OFF);

#if defined(__APPLE__)
			auto maybe_real_iface = macos_get_real_interface(wg_iface, /* quiet: */ true);
			if(maybe_real_iface.is_err())
			{
				zpr::println("{}interface {}{}{}: {}down{}", msg::BOLD, msg::GREEN, wg_iface, //
				    msg::ALL_OFF, msg::RED, msg::ALL_OFF);
				continue;
			}

			auto iface = *maybe_real_iface;
#else
			auto& iface = wg_iface;
			if(not does_interface_exist(iface))
			{
				zpr::println("{}interface {}{}{}: {}down{}", msg::BOLD, msg::GREEN, iface, //
				    msg::ALL_OFF, msg::RED, msg::ALL_OFF);
				continue;
			}
#endif

			auto maybe_proc = wg_show(iface);
			if(maybe_proc.is_err())
			{
				msg::error("{}", maybe_proc.error());
				continue;
			}

			if(auto code = maybe_proc->wait(); code != 0)
			{
				msg::error("`wg show` exited with non-zero code {}", code);
				continue;
			}

			auto iface_ip = zst::str_view(config.subnet).take_until('/');
			auto iface_cidr = zst::str_view(config.subnet).drop_until('/').drop(1);

			{
#if defined(__APPLE__)
				if(config.nickname.has_value())
				{
					zpr::println("{}interface {}{}{} ({}{}{}: {}{}{})", msg::BOLD, //
					    msg::GREEN, *config.nickname, msg::ALL_OFF,                //
					    msg::BLUE, wg_iface, msg::ALL_OFF,                         //
					    msg::BLUE, iface, msg::ALL_OFF                             //
					);
				}
				else
				{
					zpr::println("{}interface {}{}{} ({}{}{})", msg::BOLD, //
					    msg::GREEN, wg_iface, msg::ALL_OFF,                //
					    msg::BLUE, iface, msg::ALL_OFF                     //
					);
				}
#else
				if(config.nickname.has_value())
				{
					zpr::println("{}interface {}{}{} ({}{}{})", msg::BOLD, //
					    msg::GREEN, *config.nickname, msg::ALL_OFF,        //
					    msg::BLUE, wg_iface, msg::ALL_OFF,                 //
					);
				}
				else
				{
					zpr::println("{}interface {}{}{}", msg::BOLD, msg::GREEN, wg_iface, msg::ALL_OFF);
				}
#endif
			}

			zpr::println("  {}address:{}  {}{}{}{}/{}{}", msg::BOLD, msg::ALL_OFF, msg::YELLOW, iface_ip, msg::ALL_OFF,
			    msg::BLUE_NB, iface_cidr, msg::ALL_OFF);

			if(config.dns.has_value())
				zpr::println("  {}dns:{}      {}{}{}", msg::BOLD, msg::ALL_OFF, msg::PINK, *config.dns, msg::ALL_OFF);

			std::vector<std::string> lines {};
			while(true)
			{
				auto line = maybe_proc->readStdoutLine();
				if(line.empty())
					break;
				lines.push_back(std::move(line));
			}

			std::vector<std::vector<zst::str_view>> line_parts {};
			for(auto& line : lines)
				line_parts.push_back(util::split_by_spaces(line));

			std::sort(1 + line_parts.begin(), line_parts.end(), [](const auto& p1, const auto& p2) {
				if(p1.size() != 8)
					msg::error_and_exit("Malformed output from wg dump: '{}'", p1);
				if(p2.size() != 8)
					msg::error_and_exit("Malformed output from wg dump: '{}'", p2);

				auto p1_ip = p1[3];
				auto p2_ip = p2[3];

				if(p1_ip.ends_with("/32"))
					p1_ip.remove_suffix(3);

				if(p2_ip.ends_with("/32"))
					p2_ip.remove_suffix(3);

				auto to_int = [](zst::str_view sv) -> int {
					int ret = 0;
					while(not sv.empty())
					{
						ret = (10 * ret) + (sv[0] - '0');
						sv.remove_prefix(1);
					}
					return ret;
				};

				for(int i = 0; i < 4; i++)
				{
					auto a1 = p1_ip.take_until('/');
					auto a2 = p2_ip.take_until('/');

					if(a1 != a2)
						return to_int(a1) < to_int(a2);

					p1_ip.remove_prefix(a1.size() + 1);
					p2_ip.remove_prefix(a2.size() + 1);
				}

				return false;
			});


			for(size_t i = 0; i < lines.size(); i++)
			{
				auto& parts = line_parts[i];
				if(i == 0)
				{
					if(parts.size() != 4)
						msg::error_and_exit("Malformed output from wg dump: '{}'", lines[0]);

					if(show_keys)
					{
						zpr::println("  {}pubkey:{}   {}{}{}\n", msg::BOLD, msg::ALL_OFF, msg::PINK_NB, parts[1],
						    msg::ALL_OFF);
					}
					else
					{
						zpr::println("");
					}
				}
				else
				{
					auto pub_key = parts[0];
					auto endpoint_str = parts[2];
					auto ip_str_ = parts[3];
					auto last_handshake = parts[4];
					auto rx_bytes = parts[5];
					auto tx_bytes = parts[6];

					std::vector<zst::str_view> ips {};
					for(auto ip_part : util::split_by(ip_str_, ','))
					{
						if(ip_part.ends_with("/32"))
							ip_part.remove_suffix(3);

						ips.push_back(ip_part);
					}

					std::string peer_name {};
					bool unknown_peer = false;
					if(auto maybe_peer = config.lookup_peer_from_pubkey(pub_key); maybe_peer.has_value())
					{
						peer_name = maybe_peer->name;
					}
					else
					{
						unknown_peer = true;
						peer_name = "unknown";
					}

					zpr::print("  {}peer {}{}{} (", msg::BOLD, (unknown_peer ? msg::RED : msg::BLUE), peer_name,
					    msg::ALL_OFF);

					for(size_t k = 0; k < ips.size(); k++)
					{
						auto [_, cidr] = util::parse_ip(ips[k]);
						if(k > 0)
							zpr::print(", ");

						zpr::print("{}{}{}{}/{}{}", msg::YELLOW, ips[k], msg::ALL_OFF, msg::BLUE_NB, cidr,
						    msg::ALL_OFF);
					}

					zpr::println(")");

					struct
					{
						std::string endpoint;
						std::string handshake;
						std::string ago;
						std::string tx;
						std::string rx;
					} print_args;

					if(endpoint_str == "(none)")
					{
						print_args.endpoint = zpr::sprint("{}none", msg::GREY);
					}
					else
					{
						auto x = endpoint_str.find(':');
						if(x == std::string::npos)
							msg::error_and_exit("Malformed endpoint string '{}' -- missing port", endpoint_str);

						auto ip = endpoint_str.take(x);
						auto port = endpoint_str.drop(x + 1);
						print_args.endpoint = zpr::sprint("{}{}{}{}:{}", msg::PINK_NB, ip, msg::ALL_OFF, msg::GREY,
						    port);
					}

					if(last_handshake != "0")
					{
						print_args.handshake = time_to_relative_string(std::stoll(last_handshake.str()));
						print_args.ago = " ago";
					}
					else
					{
						print_args.handshake = zpr::sprint("{}never", msg::GREY);
						print_args.ago = "";
					}

					print_args.tx = bytes_to_string(static_cast<uint64_t>(std::stoull(tx_bytes.str())));
					print_args.rx = bytes_to_string(static_cast<uint64_t>(std::stoull(rx_bytes.str())));

					zpr::println("    {}conn:        {}{}{}", msg::BOLD, msg::ALL_OFF, print_args.endpoint,
					    msg::ALL_OFF);

					zpr::println("    {}last:        {}{}{}{}{}{}{}", msg::BOLD, msg::ALL_OFF, msg::PINK_NB,
					    print_args.handshake, msg::ALL_OFF, msg::BOLD, print_args.ago, msg::ALL_OFF);

					zpr::println("    {}traffic:     {}{}{}{} {}sent{}, {}{}{} {}received{}", msg::BOLD, msg::ALL_OFF,
					    msg::PINK_NB, print_args.tx, msg::ALL_OFF, msg::BOLD, msg::ALL_OFF, msg::PINK_NB, print_args.rx,
					    msg::ALL_OFF, msg::BOLD, msg::ALL_OFF);

					if(show_keys)
					{
						zpr::println("    {}pubkey:{}      {}{}{}", msg::BOLD, msg::ALL_OFF, msg::PINK_NB, pub_key,
						    msg::ALL_OFF);
					}

					zpr::println("");
				}
			}
		}
	}
}
