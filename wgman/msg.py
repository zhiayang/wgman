#!/usr/bin/env python
# Copyright (c) 2023, zhiayang
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import *

_indentation: int = 0

GREEN   = "\x1b[92;1m"
BLUE    = "\x1b[94;1m"
YELLOW  = "\x1b[93;1m"
RED     = "\x1b[91;1m"
PINK    = "\x1b[95;1m"
GREY    = "\x1b[90;1m"
WHITE   = "\x1b[97;1m"
BOLD    = "\x1b[1m"
UNCOLOUR= "\x1b[0m\x1b[1m"
ALL_OFF = "\x1b[0m"

PINK_NB = "\x1b[95m"
GREY_NB = "\x1b[90m"

def green(s: str):
	return f"{GREEN}{s}{ALL_OFF}"

def blue(s: str):
	return f"{BLUE}{s}{ALL_OFF}"

def yellow(s: str):
	return f"{YELLOW}{s}{ALL_OFF}"

def pink(s: str):
	return f"{PINK}{s}{ALL_OFF}"

def red(s: str):
	return f"{RED}{s}{ALL_OFF}"

def white(s: str):
	return f"{WHITE}{s}{ALL_OFF}"

def bold(s: str):
	return f"{BOLD}{s}{ALL_OFF}"



def log(msg: str, end: str = '\n'):
	print(f"{green('==>')} {bold(msg)}", flush=True, end=end)

def log2(msg: str, end: str = '\n'):
	print(f"{blue('  ->')} {bold(msg)}", flush=True, end=end)

def log3(msg: str, end: str = '\n'):
	print(f"{pink('    +')} {bold(msg)}", flush=True, end=end)


def warn(msg: str):
	print(f"{yellow('==> WARNING:')} {bold(msg)}", flush=True, file=sys.stderr)

def error(msg: str):
	print(f"{red('==> ERROR:')} {bold(msg)}", flush=True, file=sys.stderr)

def error_and_exit(msg: str) -> NoReturn:
	error(msg)
	sys.exit(1)

def p(msg: str, end: str = '\n'):
	global _indentation
	print(2 * _indentation * ' ' + msg, end=end, flush=True)

def indent():
	global _indentation
	_indentation += 1

def dedent():
	global _indentation
	_indentation -= 1


class Indent:
	def __init__(self):
		pass

	def __enter__(self):
		indent()

	def __exit__(self, *_: list[Any]):
		dedent()
