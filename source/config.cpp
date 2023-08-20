// config.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#define TOML_EXCEPTIONS 0
#include <toml.hpp>

#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <regex>
#include <filesystem>

#include "wgman.h"

namespace stdfs = std::filesystem;

namespace wg
{
	static std::string read_key(const std::string& key)
	{
		if(not zst::str_view(key).starts_with("file:"))
			return key;

		// skip 'file:'
		auto f = open(key.c_str() + 5, O_RDONLY);
		if(f < 0)
			msg::error_and_exit("Key file '{}' does not exist", key);

		std::string ret {};
		ret.resize(512);

		auto did_read = read(f, ret.data(), 512);
		if(did_read < 0)
			msg::error_and_exit("Failed to read file: {} ({})", strerror(errno), errno);
		else if(did_read == 0)
			msg::error_and_exit("Empty key file");

		ret.resize(static_cast<size_t>(did_read));
		close(f);

		while(not ret.empty() && (ret.back() == '\n' || ret.back() == '\r'))
			ret.pop_back();

		return ret;
	}

	Config Config::load(const std::string& filename)
	{
		auto path = stdfs::path(filename);
		path.replace_extension("");

		auto maybe_cfg = toml::parse_file(filename);
		if(not maybe_cfg)
			msg::error_and_exit("Failed to parse config: {}", maybe_cfg.error().description());

		// chdir to it so file: loads are relative to the config file
		if(path.has_parent_path())
		{
			std::error_code ec {};
			if(stdfs::current_path(path.parent_path(), ec); ec)
				msg::error_and_exit("Failed to load config file: {}", ec.message());
		}

		auto& cfg = maybe_cfg.table();
		if(not cfg.is_table())
			msg::error_and_exit("Expected top-level table");

		auto& table = *cfg.as_table();
		if(not table.contains("interface") || not table["interface"].is_table())
			msg::error_and_exit("Missing required key 'interface'");

		auto& interface = *table["interface"].as_table();
		for(auto key : { "subnet", "private-key" })
		{
			if(not interface.contains(key))
				msg::error_and_exit("Missing required key '{}' in 'interface'", key);
		}

		std::optional<int64_t> port = 0;
		if(interface.contains("port") && not interface["port"].is_integer())
			msg::error_and_exit("'port' key must be an integer");
		else if(interface.contains("port"))
			port = *interface["port"].value<int64_t>();

		if(port.has_value() && not(1 <= port && port <= 65535))
			msg::error_and_exit("'port' must be between 1 and 65535");

		std::optional<int> mtu {};
		if(interface.contains("mtu") && not interface["mtu"].is_integer())
			msg::error_and_exit("'mtu' must be an integer");
		else if(interface.contains("mtu"))
			mtu = *interface["mtu"].value<int64_t>();

		auto subnet = *interface["subnet"].value<std::string>();
		auto cidr_regex = std::regex(R"(([0-9]{1,3})(\.[0-9]{1,3}){3}/[0-9]+)");
		if(not std::regex_match(subnet, cidr_regex))
			msg::error_and_exit("Invalid 'subnet' specification; expected subnet in CIDR notation");

		std::vector<Peer> peers {};
		if(not cfg.contains("peer"))
		{
			msg::warn("No peers specified");
		}
		else if(not cfg["peer"].is_table())
		{
			msg::error_and_exit("No peers specified (or invalid type for 'peer' key");
		}
		else
		{
			for(auto& [_name, _peer] : *cfg["peer"].as_table())
			{
				auto name = _name.str();
				if(not _peer.is_table())
					msg::error_and_exit("Invalid specification for peer '{}': expected a table", name);

				auto& peer = *_peer.as_table();
				if(not peer.contains("public-key") || not peer["public-key"].is_string())
					msg::error_and_exit("Missing required key 'public-key' for peer '{}' (must be a string)", name);
				else if(not peer.contains("ip") || not peer["ip"].is_string())
					msg::error_and_exit("Missing required key 'ip' for peer '{}' (must be a string)", name);

				auto ip = *peer["ip"].value<std::string>();
				auto ip_regex = std::regex(R"(([0-9]{1,3})(\.[0-9]{1,3}){3}(/[0-9]+)?)");
				if(not std::regex_match(ip, ip_regex))
					msg::error_and_exit("Invalid IP address '{}' for peer '{}'", ip, name);

				if(ip.find("/") == std::string::npos)
					ip += "/32";

				std::optional<int> keepalive {};
				if(auto tmp = peer["keepalive"]; tmp)
				{
					if(not tmp.is_integer() && tmp != "off")
						msg::error_and_exit("'keepalive' value must be an integer (or the string 'off')");

					else if(auto k = *tmp.value<int64_t>(); not(0 <= k && k <= 65535))
						msg::error_and_exit("'keepalive' value must be between 1 and 65535");
					else
						keepalive = static_cast<int>(k);
				}

				std::optional<std::string> endpoint {};
				if(auto tmp = peer["endpoint"]; tmp)
				{
					if(not tmp.is_string())
						msg::error_and_exit("'endpoint' must be a string");

					auto ep = *peer["endpoint"].value<std::string>();
					if(not std::regex_match(ep, std::regex(R"((.+):([0-9]+))")))
						msg::error_and_exit("Expected endpoint format: '<ip/url>:<port>'");
					else
						endpoint = std::move(ep);
				}

				std::optional<std::string> psk {};
				if(auto tmp0 = peer["preshared-key"])
					psk = *tmp0.value<std::string>();
				else if(auto tmp1 = peer["pre-shared-key"])
					psk = *tmp1.value<std::string>();

				if(psk.has_value())
					psk = read_key(*psk);

				peers.push_back(Peer {
				    .name = std::string(name),
				    .ip = ip,
				    .public_key = read_key(*peer["public-key"].value<std::string>()),
				    .pre_shared_key = psk,
				    .keepalive = keepalive,
				    .endpoint = std::move(endpoint),
				});
			}
		}

		auto get_bool = [&interface](const char* key) -> bool {
			if(auto tmp = interface[key]; tmp)
			{
				if(not tmp.is_boolean())
					msg::error_and_exit("'{}' must be a boolean", key);

				return *tmp.value<bool>();
			}

			return false;
		};

		bool use_wg_quick = get_bool("use-wg-quick");
		bool auto_forward = get_bool("auto-iptables-forward");
		bool auto_masquerade = get_bool("auto-iptables-masquerade");

		if(auto_masquerade && not interface.contains("interface"))
		{
			msg::error_and_exit(
			    "Network interface (key='interface') must be specified when using "
			    "'auto-iptables-masquerade'");
		}

		return Config {
			.name = path.filename().string(),
			.interface = interface["interface"].value<std::string>(),
			.subnet = std::move(subnet),
			.port = port.has_value() ? std::optional<uint16_t>(static_cast<uint16_t>(*port)) : std::nullopt,
			.mtu = mtu,
			.use_wg_quick = use_wg_quick,
			.auto_forward = auto_forward,
			.auto_masquerade = auto_masquerade,
			.post_up_cmd = interface["post-up"].value<std::string>(),
			.post_down_cmd = interface["post-down"].value<std::string>(),
			.private_key = read_key(*interface["private-key"].value<std::string>()),
			.peers = std::move(peers),
		};
	}

	std::optional<Peer> Config::lookup_peer_from_pubkey(zst::str_view pubkey) const
	{
		for(auto& peer : this->peers)
		{
			if(peer.public_key == pubkey)
				return peer;
		}

		return std::nullopt;
	}

	std::string Config::to_wg_conf() const
	{
		std::string ret {};
		ret += "[Interface]\n";
		ret += zpr::sprint("PrivateKey = {}\n", this->private_key);
		if(this->port.has_value())
			ret += zpr::sprint("ListenPort = {}\n", *this->port);

		ret += "\n";
		for(auto& peer : this->peers)
		{
			ret += zpr::sprint("[Peer]\n");
			ret += zpr::sprint("AllowedIPs = {}\n", peer.ip);
			ret += zpr::sprint("PublicKey = {}\n", peer.public_key);

			if(peer.pre_shared_key.has_value())
				ret += zpr::sprint("PresharedKey = {}\n", *peer.pre_shared_key);
			if(peer.keepalive.has_value())
				ret += zpr::sprint("PersistentKeepalive = {}\n", *peer.keepalive);
			if(peer.endpoint.has_value())
				ret += zpr::sprint("Endpoint = {}\n", *peer.endpoint);

			ret += "\n";
		}

		return ret;
	}

	std::string Config::to_wg_quick_conf() const
	{
		std::string ret {};
		ret += "[Interface]\n";
		ret += zpr::sprint("Address = {}\n", this->subnet);
		ret += zpr::sprint("SaveConfig = false\n");
		ret += zpr::sprint("PrivateKey = {}\n", this->private_key);
		if(this->mtu.has_value())
			ret += zpr::sprint("MTU = {}\n", *this->mtu);

		if(this->port.has_value())
			ret += zpr::sprint("ListenPort = {}\n", *this->port);

		if(this->auto_forward)
		{
			ret += zpr::sprint("PostUp = iptables -I FORWARD 1 -i {} -j ACCEPT\n", this->name);
			ret += zpr::sprint("PostDown = iptables -D FORWARD -i {} -j ACCEPT\n", this->name);
		}

		if(this->auto_masquerade)
		{
			assert(this->interface.has_value());
			ret += zpr::sprint("PostUp = iptables -t nat -I POSTROUTING 1 -o {} -j MASQUERADE\n", *this->interface);
			ret += zpr::sprint("PostDown = iptables -t nat -D POSTROUTING -o {} -j MASQUERADE\n", *this->interface);
		}

		if(this->post_up_cmd.has_value())
			ret += zpr::sprint("PostUp = {}\n", *this->post_up_cmd);
		if(this->post_down_cmd.has_value())
			ret += zpr::sprint("PostDown = {}\n", *this->post_down_cmd);

		ret += "\n";
		for(auto& peer : this->peers)
		{
			ret += zpr::sprint("[Peer]\n");
			ret += zpr::sprint("AllowedIPs = {}\n", peer.ip);
			ret += zpr::sprint("PublicKey = {}\n", peer.public_key);

			if(peer.pre_shared_key.has_value())
				ret += zpr::sprint("PresharedKey = {}\n", *peer.pre_shared_key);
			if(peer.keepalive.has_value())
				ret += zpr::sprint("PersistentKeepalive = {}\n", *peer.keepalive);
			if(peer.endpoint.has_value())
				ret += zpr::sprint("Endpoint = {}\n", *peer.endpoint);

			ret += "\n";
		}

		return ret;
	}
}
