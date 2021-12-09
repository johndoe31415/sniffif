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
import time
from TempfileProcess import TempfileProcess

class TCPDumpProcess(TempfileProcess):
	def __init__(self, interface, outfile, uid_gid = None):
		TempfileProcess.__init__(self, uid_gid)
		self._interface = interface
		self._outfile = outfile
		self._start()

	def _cmdline(self):
		return [ "tcpdump", "--packet-buffered", "-i", self._interface, "-w", self._outfile, "-s", "0" ]

	def _post_start(self):
		if self._uid_gid is not None:
			for i in range(10):
				if os.path.isfile(self._outfile):
					break
				time.sleep(0.1)
			os.chown(self._outfile, self._uid_gid[0], self._uid_gid[1])

class DNSMasqProcess(TempfileProcess):
	def __init__(self, interface, dhcp_range, uid_gid = None):
		TempfileProcess.__init__(self, uid_gid)
		self._interface = interface
		self._dhcp_range = dhcp_range
		self._start()

	def _cmdline(self):
		return [ "dnsmasq", "-C", self.tmpname("config"), "-k" ]

	def _pre_start(self):
		config = self._new_tempfile("config", prefix = "dnsmasq_", suffix = ".conf", mode = "w")
		self._new_tempfile("leases", prefix = "dnsmasq_", suffix = ".leases")

		print("interface=%s" % (self._interface), file = config)
		print("bind-interfaces", file = config)
		print("dhcp-range=%s,%s,12h" % (self._dhcp_range[0], self._dhcp_range[1]), file = config)
		print("dhcp-leasefile=%s" % (self.tmpname("leases")), file = config)
		config.flush()
