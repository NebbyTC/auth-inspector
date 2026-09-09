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


def get_tty(log_line: str) -> str:
	"""
		Zwraca nazwę terminala TTY, z którego dokonano próby logowania.
	"""

	match = re.search(r'tty=(?:/dev/)?([^\s;]+)', log_line)
	return match.group(1) if match else None


def get_ip_from_tty(tty_name: str):
	"""
		Zwraca adres IP powiązany z danym terminalem TTY, jeśli istnieje.
	"""
	
	result = subprocess.run(['who'], capture_output=True, text=True, check=True)
	
	for line in result.stdout.splitlines():
		if not tty_name in line: continue

		line_splitted = line.split()

		is_not_ssh = len(line_splitted) < 5
		if is_not_ssh:
			continue

		return line_splitted[5].strip("()")
	return None


def log_incident(ip_address: str, tty_field: str, source: str) -> None:
	"""
		Zapisuje incydent do pliku logów auth-inspector.
	"""
	with open(LOG_FILE, "a", encoding="utf-8") as f:
		timestamp = time.strftime("%b %d %H:%M:%S")
		log_line = f"{timestamp} auth-inspector: {source} auth failed from IP={ip_address} on {tty_field}\n"
		
		f.write(log_line)
		logging.info(f"[Auth inspector] Zarejestrowano próbę włamania przez {source}: TTY={tty_field}, IP={ip_address}")


def monitor_sudo() -> None:
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

			tty = get_tty(message)
			ip_address = get_ip_from_tty(tty)

			local_session = not ip_address
			if local_session: continue 

			log_incident(ip_address, tty, source=comm.upper())


if __name__ == "__main__":
	# Tworzenie katalogu logów, jeśli nie istnieje
	os.makedirs(LOG_DIR, exist_ok=True)

	# Konfiguracja bezpiecznego i czytelnego logowania błędów skryptu
	logging.basicConfig(
		level=logging.INFO,
		format='%(asctime)s [%(levelname)s] %(message)s',
		handlers=[logging.StreamHandler(sys.stdout)]
	)

	# Upewniamy się, że skrypt jest uruchomiony jako root
	if os.geteuid() != 0:
		print("Ten skrypt wymaga uprawnień administratora (root)!", file=sys.stderr)
		sys.exit(1)
		
	monitor_sudo()

