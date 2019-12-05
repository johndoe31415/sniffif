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

import re
import os
import time
import requests

class OUILookup():
	_URI = "http://standards-oui.ieee.org/oui.txt"
	_LOCAL_FILENAME = "oui.txt"
	_MAC_REGEX = re.compile(r"(?P<prefix>[A-Z0-9a-f]{1,12})\s+\(base 16\)\s+(?P<company>.*)")

	def __init__(self):
		self._download_oui_file()
		self._database = self._parse_file()

	def _parse_file(self):
		db = { }
		with open(self._LOCAL_FILENAME) as f:
			for line in f:
				line = line.rstrip("\r\n\t ")
				result = self._MAC_REGEX.fullmatch(line)
				if result:
					result = result.groupdict()
					if len(result["prefix"]) % 2 == 0:
						prefix = bytes.fromhex(result["prefix"])
						db[prefix] = result["company"]
		return db

	def _download_oui_file(self):
		if os.path.isfile(self._LOCAL_FILENAME):
			age = time.time() - os.stat(self._LOCAL_FILENAME).st_mtime
			if age < 86400 * 30 * 2:
				# Less than two months old, reuse
				return

		response = requests.get(self._URI)
		if response.status_code == 200:
			with open(self._LOCAL_FILENAME, "w") as f:
				f.write(response.text)

	def lookup(self, mac_address):
		bin_mac = bytes(int(x, 16) for x in mac_address.split(":"))
		for i in range(6):
			prefix = bin_mac[: (6 - i)]
			if prefix in self._database:
				return self._database[prefix]
		return None

if __name__ == "__main__":
	lookup = OUILookup()
	print(lookup.lookup("00:11:22:33:44:55"))
