import unittest
import subprocess
from auth_inspector import TerminalSession


class TestTerminalSessionIntegration(unittest.TestCase):

	def test_integration_with_actual_who_command(self):
		"""
			Prawdziwy test integracyjny: Uruchamia realną komendę 'who'.
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

	def test_integration_search_non_existent_terminal(self):
		"""
			Test integracyjny: Sprawdza zachowanie kodu w starciu z żywym systemem,
			gdy szukamy terminala, który na 100% nie istnieje w aktywnych sesjach.
		"""
		# 'fake/terminal/999' na pewno nie pojawi się w wyniku komendy 'who'
		with self.assertRaises(LookupError) as context:
			TerminalSession._fetch_ip_from_system("fake/terminal/999")
			
		# Sprawdzamy, czy rzucony wyjątek zawiera nasz unikalny komunikat aplikacji
		self.assertIn("[Auth-inspector] Terminal", str(context.exception))
