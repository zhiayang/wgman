// main.cpp
// Copyright (c) 2023, zhiayang
// SPDX-License-Identifier: Apache-2.0

#define ZARG_IMPLEMENTATION
#include "zarg.h"

#include "wgman.h"

constexpr const char* DEFAULT_DIR = "/etc/wireguard";

static void print_help()
{
	zpr::println("Usage: wgman SUBCOMMAND [options...]\n");
	zpr::println("Subcommands:");
	zpr::println("  help                show help");
	zpr::println("  status              show the status");
	zpr::println("  up                  bring up an interface");
	zpr::println("  down                bring down an interface");
	zpr::println("");
	zpr::println("Common options:");
	zpr::println("  -h, --help          show help for a subcommand");
	zpr::println("  -v, --verbose       print verbose (more) information");
	zpr::println("  -d, --dir <DIR>     look for configs in the given directory (default: /etc/wireguard)\n");
}

static bool s_is_verbose = false;
bool wg::is_verbose()
{
	return s_is_verbose;
}

int main(int argc, char** argv)
{
	if(argc == 1)
	{
		wg::status(DEFAULT_DIR, std::nullopt, /* show keys: */ true);
	}
	else
	{
		argc -= 1;
		argv += 1;

		auto args =
		    zarg::Parser() //
		        .add_option('d', "dir", true)
		        .add_option('h', "help", false)
		        .add_option('v', "verbose", false)
		        .allow_options_after_positionals()
		        .ignore_unknown_flags()
		        .parse(argc, argv)
		        .set();

		auto dir = args.get_option("dir").value_or(DEFAULT_DIR);
		s_is_verbose = args.has_option("verbose");

		if(strcmp(argv[0], "status") == 0)
		{
			if(args.has_option("help"))
			{
				zpr::println("Usage: wgman status [options...] [INTERFACE]\n");
				zpr::println("Specify INTERFACE to print the status for just that interface, otherwise");
				zpr::println("print the status for all known WireGuard interfaces\n");

				zpr::println("Options:");
				zpr::println("  -k, --no-keys       don't print public keys\n");
				return 0;
			}

			auto sub_args =
			    zarg::Parser() //
			        .add_option('k', "no-keys", false, "")
			        .allow_options_after_positionals()
			        .parse(argc, argv)
			        .set();

			if(sub_args.positional.size() > 1)
			{
				zpr::println("Only one interface can be specified");
				exit(1);
			}

			std::optional<std::string> iface {};
			if(sub_args.positional.size() == 1)
				iface = sub_args.positional[0];

			wg::status(dir, iface, /* show_keys: */ not sub_args.has_option("no-keys"));
		}
		else if(strcmp(argv[0], "up") == 0)
		{
			if(args.has_option("help"))
			{
				zpr::println("Usage: wgman up INTERFACE\n");
				zpr::println("Bring up a WireGuard interface; its config file must exist,");
				zpr::println("but the interface must not.");
				zpr::println("Does not take additional options.");
				return 0;
			}

			if(args.positional.size() != 1)
				zpr::println("Expected exactly one interface");

			if(wg::up(wg::Config::load(zpr::sprint("{}/{}.toml", dir, args.positional[0]))).is_err())
				return 1;
		}
		else if(strcmp(argv[0], "down") == 0)
		{
			if(args.has_option("help"))
			{
				zpr::println("Usage: wgman down INTERFACE\n");
				zpr::println("Bring down an existing WireGuard interface; it must exist.");
				zpr::println("Does not take additional options.");
				return 0;
			}

			if(args.positional.size() != 1)
				zpr::println("Expected exactly one interface");

			if(wg::down(wg::Config::load(zpr::sprint("{}/{}.toml", dir, args.positional[0]))).is_err())
				return 1;
		}
		else if(strcmp(argv[0], "help") == 0)
		{
			print_help();
		}
		else
		{
			zpr::println("Unknown subcommand '{}'", argv[0]);
			print_help();
			exit(1);
		}
	}
}