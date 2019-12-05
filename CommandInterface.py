#	sniffif - Quick setup for sniffing on a network interface
#	Copyright (C) 2019-2019 Johannes Bauer
#
#	This file is part of sniffif.
#
#	sniffif is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	sniffif is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with sniffif; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import os
import sys
import inspect
import collections
import re
import time
from OUILookup import OUILookup

RegisteredCommand = collections.namedtuple("RegisteredCommand", [ "aliases", "parameters" ])
RegisteredCommandEntry = collections.namedtuple("RegisteredCommandEntry", [ "name", "handler", "registration" ])

class ExitCommandInterfaceException(Exception): pass

class CommandInterface():
	_DNSMASQ_LEASE_RE = re.compile(r"(?P<expiry>\d+)\s+(?P<mac>[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2})\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(?P<name>\S+)\s")
	def __init__(self, shared_data):
		self._shared_data = shared_data
		self._commands = self._build_commands()
		self._oui_lookup = OUILookup()

	def _build_commands(self):
		commands = { }
		for methodname in dir(self):
			if methodname.startswith("_command_"):
				method = getattr(self, methodname)
				signature = inspect.signature(method)
				name = methodname[9:]
				registration = signature.return_annotation
				entry = RegisteredCommandEntry(name = name, handler = method, registration = registration)
				commands[name] = entry
				for alias in registration.aliases:
					commands[alias] = entry
		return commands

	def _command_list(self, parameters) -> RegisteredCommand(aliases = [ "l" ], parameters = None):
		if not os.path.isfile(self._shared_data["dnsmasq_lease_file"]):
			print("No DNSMasq lease file present.", file = sys.stderr)
			return
		with open(self._shared_data["dnsmasq_lease_file"]) as f:
			entries = [ ]
			for line in f:
				line = line.rstrip("\r\n")
				result = self._DNSMASQ_LEASE_RE.match(line)
				if result:
					result = result.groupdict()
					result["expiry"] = int(result["expiry"])
					entries.append(result)

		entries.sort(key = lambda x: x["name"])
		for entry in entries:
			validity = round(entry["expiry"] - time.time())
			if validity < 0:
				validity_str = "Expired"
			else:
				validity_str = "%2d:%02d:%02d" % (validity // 3600, validity % 3600 // 60, validity % 3600 % 60)
			company = self._oui_lookup.lookup(entry["mac"])
			print("%-15s %-15s %-15s %s (%s)" % (entry["name"], entry["ip"], validity_str, entry["mac"], company or "Unknown"))

	def _command_exit(self, parameters) -> RegisteredCommand(aliases = [ "quit", "x", "q" ], parameters = None):
		raise ExitCommandInterfaceException()

	def _command_help(self, parameters) -> RegisteredCommand(aliases = [ "?" ], parameters = None):
		print("Help page:")
		for (name, entry) in sorted(self._commands.items()):
			if entry.name != name:
				continue
			print("  %s" % (entry.name))

	def exec_command(self, cmdstr):
		if cmdstr == "":
			return None

		cmds = cmdstr.split()
		if len(cmds) == 0:
			return None
		cmd = cmds[0]

		if cmd in self._commands:
			registered_command = self._commands[cmd]
			handler = registered_command.handler
			return handler(parameters = cmds[1:])
		else:
			print("No such command: %s" % (cmd), file = sys.stderr)
			return None

	def read_exec_command(self):
		try:
			cmdstr = input("> ")
		except EOFError:
			raise ExitCommandInterfaceException()
		cmdstr = cmdstr.strip()
		return self.exec_command(cmdstr)


#		elif cmd in [ "l", "list" ]:
#			with open(dnsmasq_leases.name) as f:
#				print(f.read())
#		elif (cmd in [ "s", "scan" ]) and (len(cmds) == 2):
#			target = cmds[1]
#			print("Scanning %s" % (target))
#			subprocess.check_call([ "nmap", "-n", "-p", "1-65535", target ])
#		else:
#			print("Unknown command: %s" % (cmd))

	def command_loop(self):
		try:
			while True:
				self.read_exec_command()
		except ExitCommandInterfaceException:
			pass

if __name__ == "__main__":
	shared_data = {
		"dnsmasq_lease_file":	"/tmp/x",
	}
	cif = CommandInterface(shared_data)
	cif.command_loop()
