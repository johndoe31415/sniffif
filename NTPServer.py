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

import socket
import threading
import time
import random
import datetime
from NamedStruct import NamedStruct

class NTPServer():
	_NTP_MSG = NamedStruct((
		("B", "flags"),
		("B", "peer_stratum"),
		("B", "peer_polling_interval"),
		("B", "peer_clock_precision"),
		("L", "root_delay"),
		("L", "root_dispersion"),
		("L", "reference_id"),
		("Q", "reference_ts"),
		("Q", "origin_ts"),
		("Q", "receive_ts"),
		("Q", "transmit_ts"),
	), struct_extra = ">")

	def __init__(self, port = 123, timedelta_secs = 0):
		self._port = port
		self._running = False
		self._thread = None
		self._sock = None
		self._reference_id = random.randint(0, 0xffffffff)
		self._timedelta_secs = timedelta_secs

	@classmethod
	def now_utc(cls, now_utc, port = 123):
		real_now_utc = datetime.datetime.utcnow()
		tdiff = now_utc - real_now_utc
		return cls(port = port, timedelta_secs = tdiff.total_seconds())

	def _now_ntp64bit(self):
		now = time.time() + 2208988800 + self._timedelta_secs
		integer_part = int(now)
		float_part = now - integer_part
		return ((integer_part & 0xffffffff) << 32) | (round(float_part * (2 ** 32)) & 0xffffffff)

	def _run_thread(self):
		while self._running:
			try:
				(data, source) = self._sock.recvfrom(1024)
				msg = self._NTP_MSG.unpack(data)
				tx_ts = self._now_ntp64bit()
				response = self._NTP_MSG.pack({
					"flags":					0x24,
					"peer_stratum":				2,
					"peer_polling_interval":	3,
					"peer_clock_precision":		0xe8,
					"root_delay":				round(0.0005 * 65535),
					"root_dispersion":			round(0.001 * 65535),
					"reference_id":				self._reference_id,
					"receive_ts":				tx_ts,
					"transmit_ts":				tx_ts,
					"origin_ts":				msg.transmit_ts,
					"reference_ts":				tx_ts,
				})
				self._sock.sendto(response, source)
			except socket.timeout:
				pass
			except OSError:
				break

	def run(self):
		self._running = True
		self._sock = socket.socket(type = socket.SOCK_DGRAM)
		self._sock.bind(("0.0.0.0", self._port))
		self._sock.settimeout(0.1)
		self._thread = threading.Thread(target = self._run_thread)
		self._thread.start()

		print(self._sock)

	def shutdown(self):
		self._running = False
		self._sock.close()

if __name__ == "__main__":
	ntp = NTPServer.now_utc(datetime.datetime(2019, 11, 10, 0, 0, 0))
	#ntp = NTPServer()
	ntp.run()
	try:
		input("Press RETURN to exit...")
	finally:
		ntp.shutdown()
