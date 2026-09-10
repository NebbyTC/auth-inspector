#!/usr/bin/env python3
"""
Monitor bezpieczeństwa komendy sudo dla serwera Proxmox VE.
Analizuje strumień logów systemd i eksportuje adresy IP intruzów dla Fail2Ban.

1. Github i testy dla tego kodu
2. MC Hosting
3. Research na temat opcji backupowania przy wykorzystaniu mojego serwera Proxmox VE

MIĘDZYCZAS: przypinki/rzepy na kable


Może warto ten kod przerobić tak, aby była główna klasa Connection, 
która reprezetuje połączenie SSH i posiada metody do wyciągania TTY i IP. 

Jak będzie działać ekosystem?

	1. Kod jest pisany na tym kompie
	2. Następnie jest wrzucany na githuba i tam skrzętnie testowany
	3. Jeżeli przeszedł pomyślnie przez testy, to jest wystawiany do produkcji
	4. Po zalogowaniu na serwer, wyświelta się komunikat że można zaktualizować 
	auth-inspectora po wpisaniu odpowiedniej komendy.
	5. Po zdobyciu uprawnień administratorskich możesz użyć komendy, która pobiera
	najnowszą wersję skryptu i podmienia

	6. Potem jeszcze zapytać się AI, jak najlepiej te skrypty spakować, czy do osobnego
	repo czy tego samego i ewentualnie jakie są dobre praktyki dla repo takiej usługi
	dla linuxa  
"""

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

		# Zmienione na LookupError z powody braku elementu w systemie
		raise LookupError(f"[Auth-inspector] Terminal {tty_name} was not found in active sessions.")


def on_startup() -> None:
	"""
		Wykonuje wszystkie czynności związane 
		z uruchomieniem programu.
	"""

	# Upewniamy się, że skrypt jest uruchomiony jako root
	if os.geteuid() != 0:
		print("[Auth-inspector] Error: Please run the script as root.", file=sys.stderr)
		sys.exit(1)

	# Tworzenie katalogu logów, jeśli nie istnieje
	os.makedirs(LOG_DIR, exist_ok=True)
	
	# Konfiguracja bezpiecznego i czytelnego logowania błędów skryptu
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s [%(levelname)s] %(message)s',
		handlers=[logging.StreamHandler(sys.stdout)]
	)


def log_incident(session: TerminalSession) -> None:
	"""
		Zapisuje incydent do pliku logów auth-inspector.
	"""

	timestamp = time.strftime("%b %d %H:%M:%S")
	log_line = f"{timestamp} auth-inspector: {session.fail_type} auth failed from IP={session.ip_address} on {session.tty}\n"
	
	with open(LOG_FILE, "a", encoding="utf-8") as f:
		f.write(log_line)

	logging.info(f"[Auth inspector] Zarejestrowano próbę włamania przez {session.fail_type}: TTY={session.tty_field}, IP={session.ip_address}")


def run() -> None:
	"""Główna pętla zaporowa nasłuchująca zdarzeń jądra systemd."""

	if journal is None:
		logging.warning("[System] Środowisko nie obsługuje systemd. Tryb nasłuchiwania wyłączony (symulacja testowa).")
		return
	
	try:
		reader = journal.Reader()
		reader.this_boot()
		reader.add_match(_COMM="sudo")
		reader.add_match(_COMM="su")
		reader.seek_tail()
		reader.get_previous()
	except OSError as err:
		logging.critical("Nie można uzyskać dostępu do logów systemd: %s", err)
		sys.exit(1)

	logging.info("[Auth inspector] Uruchomiono pomyślnie. Nasłuchiwanie prób włamań przez sudo...")

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
