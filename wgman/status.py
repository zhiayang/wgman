#!/usr/bin/env python
# Copyright (c) 2023, zhiayang
# SPDX-License-Identifier: Apache-2.0

import os
import time
import elevate
import subprocess
from typing import *

from wgman import msg
from wgman.config import *

def time_to_relative_string(t: int) -> str:
	diff = int(time.time()) - t
	assert diff >= 0

	days, r = divmod(diff, 86400)
	hrs, r  = divmod(r, 3600)
	mins, secs = divmod(r, 60)
	if days > 0:
		if hrs > 0:
			return f"{days}d {hrs}h"
		else:
			return f"{days}d"
	elif hrs > 0:
		return f"{hrs}h {mins}m"
	elif mins > 0:
		return f"{mins}m {secs}s"
	else:
		return f"{secs}s"

def bytes_to_str(x: int) -> str:
	if x < 1024:
		return f"{x}b"
	elif x < 1024 ** 2:
		return f"{x / 1024:.1f}k"
	elif x < 1024 ** 3:
		return f"{x / 1024**2:.1f}M"
	else:
		return f"{x / 1024**3:.1f}G"

def show_status(cfg_path: str, interface: Optional[str], show_keys: bool):
	# check if we can access the config dir
	try:
		files = os.listdir(cfg_path)
	except FileNotFoundError:
		msg.error_and_exit(f"Config path '{cfg_path}' does not exist")
	except PermissionError:
		if os.geteuid() != 0:
			# msg.log("Elevating permissions...")
			elevate.elevate(graphical=False)

			# this will never be reached
			assert False
		else:
			msg.error_and_exit(f"Permission denied while accessing '{cfg_path}'")

	# chdir to the config dir so any `file:` loads are relative to there
	os.chdir(cfg_path)

	assert files is not None
	for f in files:
		if os.path.splitext(f)[1] != ".toml":
			continue

		iface_name = os.path.splitext(os.path.basename(f))[0]
		if interface is not None and iface_name != interface:
			continue

		cfg = Config.load(f)
		print(f"{msg.BOLD}interface {msg.BOLD}{msg.GREEN}{iface_name}{msg.ALL_OFF}")

		try:
			lines = subprocess.check_output(["sudo", "wg", "show", iface_name, "dump"]).decode("utf-8").splitlines()
			for line in lines[1:]:
				pub_key, _, endpoint_str, ip_str, last_handshake, rx, tx, _ = line.split()

				peer = cfg.lookup_peer_by_pub_key(pub_key)
				if (unknown_peer := (peer is None)):
					peer = Peer(name="unknown", ip=ip_str, public_key=pub_key, pre_shared_key=None)

				if ip_str.endswith("/32"):
					ip_str = ip_str[:-3]

				name_colour = msg.RED if unknown_peer else msg.BLUE
				print(f"  {msg.BOLD}peer {name_colour}{peer.name}{msg.ALL_OFF} ({msg.YELLOW}{ip_str}{msg.ALL_OFF})")
				if show_keys:
					print(f"    {msg.BOLD}public-key:{msg.ALL_OFF}  {msg.PINK_NB}{pub_key}{msg.ALL_OFF}")

				if endpoint_str == "(none)":
					eps = f"{msg.GREY}none"
				else:
					ip, port = endpoint_str.split(':')
					eps = f"{msg.PINK_NB}{ip}{msg.ALL_OFF}{msg.GREY}:{port}"

				if int(last_handshake) != 0:
					handshake_str = time_to_relative_string(int(last_handshake))
					ago = "ago"
				else:
					handshake_str = f"{msg.GREY}never"
					ago = ""

				tx_str = bytes_to_str(int(tx))
				rx_str = bytes_to_str(int(rx))
				print(f"    {msg.BOLD}conn:        {msg.ALL_OFF}{eps}{msg.ALL_OFF}")
				print(f"    {msg.BOLD}last:        {msg.ALL_OFF}{msg.PINK_NB}{handshake_str}{msg.ALL_OFF} {msg.BOLD}{ago}{msg.ALL_OFF}")
				print(f"    {msg.BOLD}traffic:     {msg.ALL_OFF}{msg.PINK_NB}{tx_str}{msg.ALL_OFF} {msg.BOLD}sent{msg.ALL_OFF}", end='')
				print(f"{msg.ALL_OFF}, {msg.PINK_NB}{rx_str}{msg.ALL_OFF} {msg.BOLD}received{msg.ALL_OFF}")
				print(f"")

		except Exception as e:
			msg.error(f"Error while getting interface status: {str(e)}")
			continue




