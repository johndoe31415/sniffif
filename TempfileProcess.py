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

import tempfile
import subprocess
import signal
import ctypes
import os

def set_pdeathsig(sig = signal.SIGKILL):
	libc = ctypes.CDLL("libc.so.6")
	return lambda: libc.prctl(1, sig)

class TempfileProcess():
	def __init__(self, uid_gid = None):
		self._uid_gid = uid_gid
		self._tempfiles = { }
		self._proc = None

	@property
	def proc(self):
		return self._proc

	def tmpname(self, name):
		return self._tempfiles[name].name

	def _cmdline(self):
		raise NotImplementedError("Need to override this method in child class.")

	def _pre_start(self):
		pass

	def _post_start(self):
		pass

	def _new_tempfile(self, name, prefix = "tempfile_", suffix = ".tmp", mode = "wb"):
		self._tempfiles[name] = tempfile.NamedTemporaryFile(prefix = prefix, suffix = suffix, mode = mode)
		if self._uid_gid is not None:
			os.chown(self.tmpname(name), self._uid_gid[0], self._uid_gid[1])
		return self._tempfiles[name]

	def _start(self):
		assert(self._proc is None)
		self._pre_start()
		cmd = self._cmdline()
		self._proc = subprocess.Popen(cmd, preexec_fn = lambda: set_pdeathsig(signal.SIGKILL))
		self._post_start()

if __name__ == "__main__":
	class SleepProcess(TempfileProcess):
		def __init__(self, *args, **kwargs):
			TempfileProcess.__init__(self, *args, **kwargs)
			self._start()

		def _pre_start(self):
			self._new_tempfile("foo")

		def _cmdline(self):
			return [ "sleep", "10" ]

	x = SleepProcess()
	x.proc.wait()
