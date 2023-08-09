// util.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#include <unistd.h>
#include <regex>

#include "wgman.h"

namespace util
{
	std::pair<zprocpipe::Process, int> try_command(const std::string& cmd, const std::vector<std::string>& args)
	{
		auto [maybe_proc, err] = zprocpipe::runProcess(cmd, args);
		if(not maybe_proc.has_value())
			msg::error_and_exit("Failed to launch {}{#}: {}", cmd, args, err);

		auto code = maybe_proc->wait();
		return std::make_pair(std::move(*maybe_proc), code);
	}

	zst::str_view trim(zst::str_view sv)
	{
		if(sv.empty())
			return sv;

		while(sv[0] == ' ' || sv[0] == '\t' || sv[0] == '\r' || sv[0] == '\n')
			sv.remove_prefix(1);

		while(sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')
			sv.remove_suffix(1);

		return sv;
	}

	std::vector<zst::str_view> split_by_spaces(zst::str_view sv)
	{
		std::vector<zst::str_view> ret {};
		while(not sv.empty())
		{
			auto x = trim(sv.take_prefix(sv.find_first_of(" \t")));
			ret.push_back(x);

			sv = trim(sv);
		}

		return ret;
	}

	zst::Failable<int> write_to_file(int fd, const std::string& contents)
	{
		for(size_t wrote = 0; wrote < contents.size();)
		{
			auto did_write = write(fd, &contents[wrote], contents.size() - wrote);
			if(did_write <= 0)
			{
				msg::error("Failed to write to file: {} ({})", strerror(errno), errno);
				return Err(0);
			}

			wrote += static_cast<size_t>(did_write);
		}
		return Ok();
	}

	std::string replace_all(std::string str, const std::string& target, std::string replacement)
	{
		for(auto i = str.find(target); i != std::string::npos; i = str.find(target))
			str.replace(i, target.size(), replacement);

		return str;
	}

	IPSubnet parse_ip(zst::str_view ip_str)
	{
		auto ip_regex = std::regex(R"(([0-9]{1,3})(\.[0-9]{1,3}){3}(/[0-9]+)?)");
		if(not std::regex_match(ip_str.begin(), ip_str.end(), ip_regex))
			msg::error_and_exit("Invalid IP address '{}'", ip_str);

		uint32_t ip32 = 0;

		auto tmp = ip_str.find('/');
		auto cidr_str = (tmp == std::string::npos ? "" : ip_str.drop(tmp + 1));
		if(tmp != std::string::npos)
			ip_str = ip_str.take(tmp);

		while(not ip_str.empty())
		{
			auto i = ip_str.find('.');
			auto octet_str = (i == std::string::npos ? ip_str.take_prefix(ip_str.size()) : ip_str.take_prefix(i));
			ip_str.remove_prefix(1);

			auto octet = static_cast<uint32_t>(std::stoul(octet_str.str()));
			if(octet > 255)
				msg::error_and_exit("Invalid IPv4 address: octet '{}' is bogus", octet);

			ip32 <<= 8;
			ip32 |= octet;
		}

		int cidr = 32;
		if(not cidr_str.empty())
		{
			cidr = std::stoi(cidr_str.str());
			if(cidr > 32)
				msg::error_and_exit("Invalid IPv4 CIDR: subnet must be < 32");
		}

		return {
			.ip = ip32,
			.cidr = cidr,
		};
	}

	bool subnet_contains_ip(zst::str_view subnet_str, zst::str_view ip_str)
	{
		auto subnet = parse_ip(subnet_str);
		auto ip = parse_ip(ip_str).ip; // ignore the cidr of the ip

		uint32_t mask = static_cast<uint32_t>(((1ull << subnet.cidr) - 1ull) << (32 - subnet.cidr));
		return (subnet.ip & mask) == (ip & mask);
	}
}
