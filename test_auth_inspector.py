import unittest
from unittest.mock import patch, MagicMock
import subprocess

# Importujemy funkcje z Twojego oryginalnego pliku skryptu
from auth_inspector import get_tty, get_ip_from_tty

class TestAuthInspector(unittest.TestCase):

	def test_get_tty_valid_line(self):
		"""Testuje, czy funkcja poprawnie wyciąga TTY z logu systemd."""
		log_line = "pam_unix(sudo:auth): authentication failure; tty=/dev/pts/2 user=prezes"
		result = get_tty(log_line)
		self.assertEqual(result, "pts/2")

	def test_get_tty_no_tty_in_line(self):
		"""Testuje zachowanie funkcji, gdy w logu brakuje parametru tty."""
		log_line = "pam_unix(sudo:auth): authentication failure; user=prezes"
		result = get_tty(log_line)
		self.assertIsNone(result)

	@patch('subprocess.run')
	def test_get_ip_from_tty_not_found(self, mock_run):
		"""Testuje zachowanie, gdy podany terminal nie jest zalogowany w systemie."""
		fake_who_output = "root     pts/2        2026-09-08 13:37\nprezes   sshd pts/1   2026-09-08 13:35 (192.168.1.104)\nprezes   sshd pts/0   2026-09-08 11:29 (192.168.1.104)"
		
		mock_response = MagicMock()
		mock_response.stdout = fake_who_output
		mock_run.return_value = mock_response

		# Szukamy pts/99, którego nie ma w fake_who_output
		ip = get_ip_from_tty("pts/99")
		self.assertIsNone(ip)


if __name__ == '__main__':
	unittest.main()
