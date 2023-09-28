// wgman.h
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>
#include <optional>

#include "zpr.h"
#include "zst.h"
#include "zprocpipe.h"

using zst::Ok;
using zst::Err;
using zst::Result;
using zst::Failable;

namespace impl
{
	template <typename T, typename E>
	struct extract_value_or_return_void
	{
		T extract(zst::Result<T, E>& result) { return std::move(result.unwrap()); }
	};

	template <typename E>
	struct extract_value_or_return_void<void, E>
	{
		void extract([[maybe_unused]] zst::Result<void, E>& result) { }
	};
}

#define __TRY(x, L)                                                 \
	__extension__({                                                 \
		auto&& __r##L = x;                                          \
		using R = std::decay_t<decltype(__r##L)>;                   \
		using V = typename R::value_type;                           \
		using E = typename R::error_type;                           \
		if((__r##L).is_err())                                       \
			return Err(std::move((__r##L).error()));                \
		impl::extract_value_or_return_void<V, E>().extract(__r##L); \
	})

#define _TRY(x, L) __TRY(x, L)
#define TRY(x) _TRY(x, __COUNTER__)

namespace wg
{
	struct Peer
	{
		std::string name;
		std::string ip;
		std::string public_key;
		std::optional<std::string> pre_shared_key;
		std::optional<int> keepalive;
		std::optional<std::string> endpoint;
		std::vector<std::string> extra_routes;
	};

	struct Config
	{
		std::string name;
		std::optional<std::string> nickname;
		std::optional<std::string> interface;
		std::string subnet;
		std::optional<uint16_t> port;
		std::optional<int> mtu;
		std::optional<std::string> dns;

		bool use_wg_quick;
		bool auto_forward;
		bool auto_masquerade;
		std::optional<std::string> post_up_cmd;
		std::optional<std::string> post_down_cmd;
		std::string private_key;
		std::vector<Peer> peers;

		static Config load(const std::string& filename);

		std::string to_wg_conf() const;
		std::string to_wg_quick_conf() const;
		std::optional<Peer> lookup_peer_from_pubkey(zst::str_view pubkey) const;
	};

	bool is_verbose();

	enum class perms
	{
		NONE,
		ROOT,
		CAPABLE,
	};

	perms check_perms();
	void set_ambient_perms();
	void reset_ambient_perms();

	zst::Failable<int> up(const Config& config);
	zst::Failable<int> down(const Config& config);
	zst::Failable<int> restart(const Config& config);
	void status(const std::string& config_path, const std::optional<std::string>& interface, bool show_keys);
}


namespace msg
{
	static constexpr const char* GREEN = "\x1b[92;1m";
	static constexpr const char* BLUE = "\x1b[94;1m";
	static constexpr const char* YELLOW = "\x1b[93;1m";
	static constexpr const char* RED = "\x1b[91;1m";
	static constexpr const char* PINK = "\x1b[95;1m";
	static constexpr const char* GREY = "\x1b[90;1m";
	static constexpr const char* WHITE = "\x1b[97;1m";
	static constexpr const char* BOLD = "\x1b[1m";
	static constexpr const char* UNCOLOUR = "\x1b[0m\x1b[1m";
	static constexpr const char* ALL_OFF = "\x1b[0m";

	static constexpr const char* PINK_NB = "\x1b[95m";
	static constexpr const char* GREY_NB = "\x1b[90m";
	static constexpr const char* BLUE_NB = "\x1b[94m";

	template <bool endl = true, typename... Args>
	void log(const char* fmt, Args&&... args)
	{
		zpr::print("{}==>{} {}{}{}{}", GREEN, ALL_OFF, BOLD, zpr::fwd(fmt, static_cast<Args&&>(args)...), ALL_OFF,
		    endl ? "\n" : "");
		fflush(stdout);
	}

	template <bool endl = true, typename... Args>
	void log2(const char* fmt, Args&&... args)
	{
		zpr::print("{}  ->{} {}{}{}{}", BLUE, ALL_OFF, BOLD, zpr::fwd(fmt, static_cast<Args&&>(args)...), ALL_OFF,
		    endl ? "\n" : "");
		fflush(stdout);
	}

	template <bool endl = true, typename... Args>
	void log3(const char* fmt, Args&&... args)
	{
		zpr::print("{}    +{} {}{}", PINK, ALL_OFF, zpr::fwd(fmt, static_cast<Args&&>(args)...), endl ? "\n" : "");
		fflush(stdout);
	}

	template <bool endl = true, typename... Args>
	void warn(const char* fmt, Args&&... args)
	{
		zpr::print("{}==> WARNING:{} {}{}{}{}", YELLOW, ALL_OFF, BOLD, zpr::fwd(fmt, static_cast<Args&&>(args)...),
		    ALL_OFF, endl ? "\n" : "");
		fflush(stdout);
	}

	template <bool endl = true, typename... Args>
	Err<int> error(const char* fmt, Args&&... args)
	{
		zpr::print("{}==> ERROR:{} {}{}{}{}", RED, ALL_OFF, BOLD, zpr::fwd(fmt, static_cast<Args&&>(args)...), ALL_OFF,
		    endl ? "\n" : "");
		fflush(stdout);
		return Err(0);
	}

	template <bool endl = true, typename... Args>
	[[noreturn]] void error_and_exit(const char* fmt, Args&&... args)
	{
		error(fmt, static_cast<Args&&>(args)...);
		exit(1);
	}
}

namespace util
{
	std::pair<zprocpipe::Process, int> try_command(const std::string& cmd, const std::vector<std::string>& args);

	struct IPSubnet
	{
		uint32_t ip;
		int cidr;
	};

	IPSubnet parse_ip(zst::str_view ip);
	bool subnet_contains_ip(zst::str_view subnet, zst::str_view ip);

	zst::Result<zst::unique_span<uint8_t[]>, int> read_entire_file(const std::string& path);
	zst::Failable<int> write_to_file(int fd, const std::string& contents);

	zst::str_view trim(zst::str_view sv);
	std::vector<zst::str_view> split_by_spaces(zst::str_view sv);
	std::vector<zst::str_view> split_by(zst::str_view sv, char ch);

	std::string replace_all(std::string str, const std::string& target, std::string replacement);

	template <typename Fn>
	struct Defer
	{
		Defer(Fn f) : fn(f) { }
		~Defer()
		{
			if(not disarmed)
				fn();
		}

		void disarm() { disarmed = true; }

		Fn fn;
		bool disarmed = false;
	};

	template <typename Fn>
	auto defer(Fn&& fn)
	{
		return Defer(static_cast<Fn&&>(fn));
	}
}

inline void zst::error_and_exit(const char* str, size_t len)
{
	msg::error_and_exit("{}", zst::str_view(str, len));
}
