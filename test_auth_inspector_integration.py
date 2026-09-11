import unittest
import subprocess
import shutil
import os
from auth_inspector import TerminalSession, log_incident, on_startup, LOG_DIR, LOG_FILE


class TestTerminalSessionIntegration(unittest.TestCase):


	def remove_logs(self):
		"""
			Usuwa pliki logów powstałe w wyniku działania programu.
		"""

		if os.path.exists(LOG_DIR):
			shutil.rmtree(LOG_DIR)

	def setUp(self):
		"""
			Przygotowanie przed każdym testem.
		"""

		self.remove_logs()

	def tearDown(self):
		"""
			Sprzątanie po każdym teście.
		"""

		self.remove_logs()

	def test_with_actual_who_command(self):
		"""
			Uruchamia realną komendę 'who'.
			Sprawdza, czy system zwraca dane w oczekiwanym formacie i czy
			nasz kod nie wywala się na rzeczywistym strumieniu stdout.
		"""
		try:
			# Wywołujemy prawdziwą komendę, dokładnie tak jak robi to nasz skrypt
			result = subprocess.run(['who'], capture_output=True, text=True, check=True)
			
			# Sprawdzamy stabilność środowiska: czy komenda cokolwiek zwróciła
			print(f"\n[INFO] Realny wynik 'who' na tym serwerze:\n{result.stdout}")
			
		except (subprocess.SubprocessError, FileNotFoundError) as e:
			self.fail(f"Test integracyjny nie powiódł się: Komenda 'who' jest niedostępna! Błąd: {e}")

	def test_search_non_existent_terminal(self):
		"""
			Sprawdza zachowanie kodu w starciu z żywym systemem,
			gdy szukamy terminala, który na 100% nie istnieje w aktywnych sesjach.
		"""
		# 'fake/terminal/999' na pewno nie pojawi się w wyniku komendy 'who'
		with self.assertRaises(LookupError) as context:
			TerminalSession._fetch_ip_from_system("fake/terminal/999")
			
		# Sprawdzamy, czy rzucony wyjątek zawiera nasz unikalny komunikat aplikacji
		self.assertIn("[Auth-inspector] Terminal", str(context.exception))


	def test_log_directory_creation(self):
		"""
			Sprawdza czy jeżeli folder logów jeszcze nie istnieje to zostanie stworzony przez skrypt.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Błąd: Folder z logami({LOG_DIR}) programu już istniał przed wykonaniem testu, a nie powinien."
		)

		on_startup()

		self.assertTrue(
			os.path.exists(LOG_DIR), 
			f"Błąd: Folder z logami({LOG_DIR}) programu nie został utworzony pomimo jego braku."
		)
		

	def test_log_saving(self):
		"""
			Sprawdza czy plik logów zapisywanych na dysku został poprawnie utworzony.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Błąd: Folder z logami({LOG_DIR}) programu już istniał przed wykonaniem testu, a nie powinien."
		)

		on_startup()
		log_incident(TerminalSession("sudo", "pts/1", "192.168.1.104"))

		self.assertTrue(
			os.path.exists(LOG_DIR), 
			f"Błąd: Plik logu nie został utworzony w lokalizacji {LOG_DIR}"
		)


	def test_log_saved_content(self):
		"""
			Testuje czy zawartość pojedyńczej linijki plik logów jest poprawna.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Błąd: Folder z logami({LOG_DIR}) programu już istniał przed wykonaniem testu, a nie powinien."
		)

		session = TerminalSession("sudo", "pts/1", "192.168.1.104")

		on_startup()
		log_incident(session)

		with open(LOG_FILE, "r") as f:
			file_content = f.read()
		
		self.assertIn("SUDO", session.fail_type, "Błąd: Program nie zapisuje poprawnie informacji o rodzaju błędnego uwierzytelnienia.")
		self.assertIn("pts/1", session.tty, "Błąd: Program nie zapisuje poprawnie informacji o identyfikatorze TTY logowanej sessji.")
		self.assertIn("192.168.1.1", session.ip_address, "Błąd: Program nie zapisuje poprawnie informacji o adresie IP logowanej sesji.")


	def test_log_saving_line_count(self):
		"""
			Testuje czy jednemu wywołaniu funkcji .log_incident() 
			odpowiada dokładnie jedna zapisana linijka.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Błąd: Folder z logami({LOG_DIR}) programu już istniał przed wykonaniem testu, a nie powinien."
		)
		
		session = TerminalSession("sudo", "pts/1", "192.168.1.104")
		on_startup()

		for i in range(2):
			log_incident(session)
			
			with open(LOG_FILE, "r") as f:
				line_count = len(f.redlines())

			self.assertEqual(line_count, i + 1)
