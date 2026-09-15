#!/usr/bin/env python3
import logging
import os
import subprocess
import sys
import time
import re

try:
	from systemd import journal 
except ModuleNotFoundError:
	journal = None


LOG_DIR = "/var/log/auth-inspector"
LOG_FILE = LOG_DIR + "/incidents.log"


class TerminalSession:
	"""
		Represents a terminal, from which someone tried to authenticate.
	"""

	def __init__(self, fail_type: str, tty: str, ip_address: str | None):
		"""
			Assigns key session attributes to the object.
		"""
		
		self.fail_type = fail_type.upper()
		self.tty = tty
		self.ip_address = ip_address
		
	def is_local(self) -> bool:
		"""
			Determines whether the terminal session represented by the object 
			is local.
		"""
		return not bool(self.ip_address)

	@classmethod
	def from_log_line(cls, message: str, fail_type: str):
		"""
			Creates a functioning session object.
		"""
		
		tty = cls._extract_tty(message)
		ip_address = cls._fetch_ip_from_system(tty)

		return cls(fail_type=fail_type, tty=tty, ip_address=ip_address)

	@staticmethod
	def _extract_tty(log_line: str) -> str:
		"""
			Returns the id of the terminal with the failed authentication try.
		
			Raises:
				String -> TTY id extracted from the given log line.
			
				RuntimeError -> if any information about TTY tag inside 
				the given entry was not found.
		"""
		
		match = re.search(r'tty=(?:/dev/)?([^\s;]+)', log_line)
		if not match: 
			raise LookupError("[Auth-inspector] Couldn't find TTY information.")
		
		return match.group(1)

	@staticmethod
	def _fetch_ip_from_system(tty_name: str) -> str | None:
		"""
			Returns an IP addres tied to the given tty terminal, if exists.
		
			Returns:
				str -> IP address tied to the given TTY id.
			
				None -> if the given terminal session turns out to be a local one.
		
			Raises:
				RuntimeError -> if a terminal with given tty id was not found.
		"""
		
		result = subprocess.run(['who'], capture_output=True, text=True, check=True)
		
		for terminal_data in result.stdout.splitlines():
			incorrect_terminal = not tty_name in terminal_data
			if incorrect_terminal: continue
		
			data_splitted = terminal_data.split()
		
			is_not_ssh = len(data_splitted) < 5
			if is_not_ssh:
				return None
		
			return data_splitted[5].strip("()")

		raise LookupError(f"[Auth-inspector] Terminal {tty_name} was not found in active sessions.")


def on_startup() -> None:
	"""
		Does all the program start up chores
	"""

	# Ensuring that the script runs as root
	if os.geteuid() != 0:
		print("[Auth-inspector] Error: Please run the script as root.", file=sys.stderr)
		sys.exit(1)

	# Creating the log directory if it doesn't exist 
	os.makedirs(LOG_DIR, exist_ok=True)
	
	# Configuring the error logging part
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s [%(levelname)s] %(message)s',
		handlers=[logging.StreamHandler(sys.stdout)]
	)


def log_incident(session: TerminalSession) -> None:
	"""
		Logs the incident to the auth-inspector log file.
	"""

	timestamp = time.strftime("%b %d %H:%M:%S")
	log_line = f"{timestamp} auth-inspector: {session.fail_type} auth failed from IP={session.ip_address} on {session.tty}\n"
	
	with open(LOG_FILE, "a", encoding="utf-8") as f:
		f.write(log_line)

	logging.info(f"[Auth inspector] Failed auth attempt on {session.fail_type}: TTY={session.tty}, IP={session.ip_address}")


def run() -> None:
	"""
		The main loop that listens to the systemd core events.
	"""

	if journal is None:
		logging.warning("[Auth inspector] OS doesn't support systemd. Listening mode activated (test simulation).")
		return
	
	try:
		reader = journal.Reader()
		reader.this_boot()
		reader.add_match(_COMM="sudo")
		reader.add_match(_COMM="su")
		reader.seek_tail()
		reader.get_previous()
	except OSError as err:
		logging.critical("[Auth inspector] Cannot reach systemd logs: %s", err)
		sys.exit(1)

	logging.info("[Auth inspector] Start successful. Listening for authentication attempts...")

	while True:
		if reader.wait() == journal.NOP:
			continue
		
		for entry in reader:
			comm = entry.get('_COMM', '')
			message = entry.get('MESSAGE', '')
			if not "authentication failure" in message: continue

			session = TerminalSession.from_log_line(message, comm)
			if session.is_local():
				continue

			log_incident(session)


if __name__ == "__main__":
	on_startup()
	run()
