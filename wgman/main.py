#!/usr/bin/env python
# Copyright (c) 2023, zhiayang
# SPDX-License-Identifier: Apache-2.0

import os
import click
import psutil
import elevate
import subprocess
from typing import *

from wgman import msg, status
from wgman.config import *

# dumb library
class NaturalOrderGroup(click.Group):
	def list_commands(self, ctx: Any) -> Any:
		return self.commands.keys()


DEFAULT_DIR = "/etc/wireguard"
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS, cls=NaturalOrderGroup)
@click.pass_context
@click.option("-d", "--dir", default=DEFAULT_DIR,
			  required=False,
			  help="The config file directory to use (defaults to /etc/wireguard)")
def cli(ctx: Any, dir: str) -> int:
	ctx.meta["config_dir"] = dir
	return 0


@cli.command(name="up")
@click.pass_context
@click.argument("interface", required=True)
def interface_up(ctx: Any, interface: str):
	"""Bring up the interface"""

	path = f"{ctx.meta['config_dir']}/{interface}.toml"

	# check if we can access the config dir
	try:
		os.stat(path)
	except FileNotFoundError:
		msg.error_and_exit(f"Config file '{path}' does not exist")
	except PermissionError:
		if os.geteuid() != 0:
			msg.log("Elevating permissions...")
			elevate.elevate(graphical=False)
		else:
			msg.error_and_exit(f"Permission denied while accessing '{path}'")

	# chdir to the config dir so any `file:` loads are relative to there
	os.chdir(ctx.meta["config_dir"])

	msg.log(f"Loading {path}")

	wg_path = f"{os.path.splitext(path)[0]}.conf"
	wg_conf = Config.load(path).make_wg_conf()
	msg.log(f"Writing WireGuard conf to {wg_path}")

	try:
		if os.path.exists(wg_path):
			msg.log2("Removing existing config")
			os.remove(wg_path)
		with open(wg_path, "w", opener=lambda p, f: os.open(p, f | os.O_TRUNC | os.O_CREAT, 0o066)) as f:
			f.write(wg_conf)
	except PermissionError:
		msg.error_and_exit(f"Permission denied while writing")

	msg.log("Bringing interface online")
	if interface in psutil.net_if_addrs().keys():
		msg.log2("Bringing down existing interface")
		try:
			subprocess.check_call(["wg-quick", "down", interface])
		except Exception as e:
			msg.error_and_exit(f"Failed to bring down interface: {str(e)}")

	try:
		subprocess.check_call(["wg-quick", "up", interface])
	except Exception as e:
		msg.error_and_exit(f"Failed to bring up interface: {str(e)}")

	msg.log("Done")


@cli.command(name="down")
@click.pass_context
@click.argument("interface", required=True)
def interface_down(ctx: Any, interface: str):
	"""Bring down the interface"""
	if interface not in psutil.net_if_addrs().keys():
		msg.error_and_exit(f"Interface '{interface}' does not exist")

	if os.geteuid() != 0:
		msg.log("Elevating permissions...")
		elevate.elevate(graphical=False)

	try:
		subprocess.check_call(["wg-quick", "down", interface])
	except Exception as e:
		msg.error_and_exit(f"Failed to bring down interface: {str(e)}")

	msg.log("Done")






@cli.command(name="status")
@click.pass_context
@click.argument("interface", required=False)
@click.option("-k", "--show-keys", is_flag=True, help="Show public keys")
def show_status(ctx: Any, interface: Optional[str], show_keys: bool):
	status.show_status(ctx.meta['config_dir'], interface, show_keys)







def main() -> int:
	return cli()
