#!/usr/bin/env python3
import os
import sys
import logging

try:
	from systemd import journal 
except ModuleNotFoundError:
	journal = None


LOG_DIR = "/var/log/auth-inspector"
LOG_FILE = LOG_DIR + "/incidents.log"


def is_root() -> bool:
	"""
		Checks if the program is running as root.
	"""

	if os.geteuid() != 0:
		return False
	return True

def on_startup() -> None:
	"""
		Does all the program start up chores
	"""

	# Ensuring that the script runs as root
	if not is_root():
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

def run() -> None:

	try:
		reader = journal.Reader()
		reader.seek_tail()
		reader.get_previous()

		reader.add_match(SYSLOG_IDENTIFIER="audisp-syslog")

	except OSError as err:
		print(f"Error: Could not acces Systemd Journal: {err}", file=sys.stderr)
		sys.exit(1)

	except NameError:
		print("Error: Dependency systemd.journal not found. Please run: apt install python3-systemd", file=sys.stderr)
		sys.exit(1)

	logging.info("[Auth inspector] Start successful. Listening for authentication attempts...")
	interesujace_typy = ["type=CRED_ACQ", "type=LOGIN", "type=USER_AUTH", "type=CRED_DISP", "type=USER_END"]

	while True:
		if reader.wait() == journal.NOP:
			continue
		
		for entry in reader:
			message = entry.get('MESSAGE', '')

			if any(typ in message for typ in interesujace_typy):
				print(message.strip())

if __name__ == "__main__":
	on_startup()
	run()
