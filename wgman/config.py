#!/usr/bin/env python
# Copyright (c) 2023, zhiayang
# SPDX-License-Identifier: Apache-2.0

import os
import re
import tomllib

from typing import *
from dataclasses import dataclass

from wgman import msg

DEFAULT_MTU = 1400

@dataclass(frozen=True, eq=True, kw_only=True)
class Peer:
	name: str
	ip: str
	public_key: str
	pre_shared_key: Optional[str]

@dataclass(frozen=True, eq=True, kw_only=True)
class Config:
	name: str
	subnet: str
	mtu: Optional[int]
	post_up_cmd: Optional[str]
	post_down_cmd: Optional[str]
	interface: Optional[str]
	port: int
	private_key: str
	peers: list[Peer]

	def make_wg_conf(self) -> str:
		lines: list[str] = ["[Interface]"]
		lines.append(f"Address = {self.subnet}")
		lines.append(f"SaveConfig = false")
		lines.append(f"ListenPort = {self.port}")
		lines.append(f"PrivateKey = {self.private_key}")
		if self.mtu is not None:
			lines.append(f"MTU = {self.mtu}")

		if (self.post_up_cmd is not None) and (self.post_down_cmd is not None):
			lines.append(f"PostUp = {self.post_up_cmd}")
			lines.append(f"PostDown = {self.post_down_cmd}")

		elif self.interface is not None:
			lines.append(f"PostUp = iptables -I FORWARD 1 -i {self.name} -j ACCEPT; "
				+ f"iptables -t nat -I POSTROUTING 1 -o {self.interface} -j MASQUERADE")

			lines.append(f"PostDown = iptables -D FORWARD -i {self.name} -j ACCEPT; "
				+ f"iptables -t nat -D POSTROUTING -o {self.interface} -j MASQUERADE")

		lines.append("")

		for peer in self.peers:
			lines.append(f"[Peer]")
			lines.append(f"AllowedIPs = {peer.ip}")
			lines.append(f"PublicKey = {peer.public_key}")
			if peer.pre_shared_key is not None:
				lines.append(f"PresharedKey = {peer.pre_shared_key}")

			# empty line
			lines.append("")

		return "\n".join(lines)

	def lookup_peer_by_pub_key(self, key: str) -> Optional[Peer]:
		for peer in self.peers:
			if peer.public_key == key:
				return peer

		return None

	@staticmethod
	def load(file: str) -> "Config":
		with open(file, "rb") as f:
			cfg: dict[str, Any] = tomllib.load(f)

		if "server" not in cfg:
			msg.error_and_exit(f"Missing required key 'server'")
		elif "subnet" not in cfg["server"]:
			msg.error_and_exit(f"Missing required key 'subnet' in 'server'")
		elif "port" not in cfg["server"]:
			msg.error_and_exit(f"Missing required key 'port' in 'server'")
		elif "private-key" not in cfg["server"]:
			msg.error_and_exit(f"Missing required key 'private-key' in 'server'")

		srv_cfg = cfg["server"]
		if not isinstance(srv_cfg["port"], int):
			msg.error_and_exit(f"'port' key must be an integer")
		elif not (1 <= srv_cfg["port"] <= 65535):
			msg.error_and_exit(f"'port' must be between 1 and 65535")

		if ("mtu" in srv_cfg) and (not isinstance(srv_cfg["mtu"], int)):
			msg.error_and_exit(f"'mtu' key must be an integer")

		if not re.fullmatch(r"([0-9]{1,3})(\.[0-9]{1,3}){3}/[0-9]+", srv_cfg["subnet"]):
			msg.error_and_exit("Invalid 'subnet' specification; expected subnet in CIDR notation")

		peers: list[Peer] = []
		if "peer" not in cfg:
			msg.warn(f"No peers specified")
		elif not isinstance(cfg["peer"], dict):
			msg.error_and_exit("Invalid type of peer list")
		else:
			name: str
			pcfg: dict[str, Any]
			for name, pcfg in cfg["peer"].items():
				if "public-key" not in pcfg:
					msg.error_and_exit(f"Missing required key 'public-key' for peer '{name}'")
				elif "ip" not in pcfg:
					msg.error_and_exit(f"Missing required key 'ip' for peer '{name}'")

				ip = cast(str, pcfg["ip"])
				if not re.fullmatch(r"([0-9]{1,3})(\.[0-9]{1,3}){3}(/[0-9]+)?", ip):
					msg.error_and_exit(f"Invalid IP address for peer '{name}'")

				if '/' not in ip:
					ip = f"{ip}/32"

				if (psk_ := cast(dict[str, Any], pcfg).get("pre-shared-key")) is not None:
					psk = Config.read_key(psk_)
				else:
					psk = None

				peers.append(Peer(name=cast(str, name), ip=ip,
					public_key=Config.read_key(cast(str, pcfg["public-key"])),
					pre_shared_key=psk))

		return Config(
			name=os.path.splitext(os.path.basename(file))[0],
			subnet=srv_cfg["subnet"],
			port=srv_cfg["port"],
			private_key=Config.read_key(srv_cfg["private-key"]),
			mtu=srv_cfg.get("mtu"),
			post_up_cmd=srv_cfg.get("post-up"),
			post_down_cmd=srv_cfg.get("post-down"),
			interface=srv_cfg.get("interface"),
			peers=peers
		)

	@staticmethod
	def read_key(key: str) -> str:
		if key.startswith(f"file:"):
			path = key[len("file:"):]
			if not os.path.exists(path):
				msg.error_and_exit(f"File '{path}' does not exist")
			return open(path, "r").read().strip()
		else:
			return key