#!/usr/bin/env python3
import os
import sys
import logging
import enum
import time

try:
	from systemd import journal 
except ModuleNotFoundError:
	journal = None


LOG_DIR = "/var/log/auth-inspector"
LOG_FILE = LOG_DIR + "/incidents.log"


class Action(enum.Enum):
	SSH_CONNECT = "CRED_ACQ"
	SSH_AUTH_ATTEMPT = "USER_AUTH"
	SSH_DISCONNECT = "CRED_DISP"

	UNKNOWN = "UNKNOWN"  

	@classmethod
	def _missing_(cls, value):
		return cls.UNKNOWN


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

def parse_audit_message(message: str) -> dict:
	"""
		Parses a raw audit message line into a clean dictionary.
		Splits by '=' and automatically strips any quotes around values.
	"""

	result = {}
	for el in message.strip().split():
		if '=' in el:
			key, value = el.split('=', 1)
			result[key] = value.strip('"\'')

	return result

def log_incident(fail_type: str, ip_address: str) -> None:
	"""
		Logs the incident to the auth-inspector log file.
	"""

	timestamp = time.strftime("%b %d %H:%M:%S")
	log_line = f"{timestamp} auth-inspector: Failed {fail_type} auth attempt from IP={ip_address}\n"
	
	with open(LOG_FILE, "a", encoding="utf-8") as f:
		f.write(log_line)

	logging.info(f"[Auth inspector] Failed auth attempt on {fail_type} from IP={ip_address}")

def on_log_line_recieve(logged_action, session_to_ip):
	"""
		Responsible for handling a single 
		log line recived by the program.
	"""

	action_type = Action(logged_action["type"])
	if action_type == Action.UNKNOWN: return
	
	if action_type == Action.SSH_CONNECT:
		invalid_action = logged_action["AUID"] == "unset"
		if invalid_action: return
	
		session_to_ip[logged_action["ses"]] = logged_action["addr"]
	
	elif action_type == Action.SSH_DISCONNECT:
		del session_to_ip[logged_action["ses"]]
	
	elif action_type == Action.SSH_AUTH_ATTEMPT:
		auth_failed = logged_action["res"] == "failed"
		if not auth_failed: return
		if not logged_action["ses"] in session_to_ip: return# <-- this should be reported as sussy behaviour(should never happen!)
	
		log_incident(logged_action["exe"], session_to_ip[logged_action["ses"]])

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
	#interesujace_typy = ["type=CRED_ACQ", "type=LOGIN", "type=USER_AUTH", "type=CRED_DISP", "type=USER_END"]

	session_to_ip = {}
	while True:
		if reader.wait() == journal.NOP:
			continue
		
		for entry in reader:
			logged_action = parse_audit_message(entry.get('MESSAGE', ''))
			on_log_line_recieve(logged_action, session_to_ip)



if __name__ == "__main__":
	on_startup()
	run()
