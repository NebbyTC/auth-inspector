import unittest
from unittest.mock import patch, MagicMock
import subprocess

from auth_inspector import TerminalSession

class TestTerminalSession(unittest.TestCase):


	fake_who_output = "root     pts/2        2026-09-08 13:37\nprezes   sshd pts/1   2026-09-08 13:35 (192.168.1.104)\nprezes   sshd pts/0   2026-09-08 11:29 (192.168.1.104)"


	def test_get_tty_valid_return(self):
		""" 
			Testuje, czy funkcja poprawnie wyciąga TTY z logu systemd. 
		"""

		session = TerminalSession(fail_type="", tty=None, ip_address=None)

		log_line = "pam_unix(sudo:auth): authentication failure; tty=/dev/pts/2 user=prezes"
		result = session._extract_tty(log_line)
		self.assertEqual(result, "pts/2")


	@patch('subprocess.run')
	def test_get_ip_vaild_return(self, mock_run):
		""" 
			Testuje, czy funkcja poprawnie wyciąga IP z wyniku polecenia who. 
		"""

		mock_response = MagicMock()
		mock_response.stdout = __class__.fake_who_output
		mock_run.return_value = mock_response

		session = TerminalSession(fail_type="", tty=None, ip_address=None)

		ip = session._fetch_ip_from_system("pts/1")
		self.assertEqual(ip, "192.168.1.104")


	def test_is_local_returns_false(self):
		"""
			Testuje, czy metoda .is_local() poprawnie rozpoznaje sesję shh.
		"""

		session = TerminalSession(fail_type="sudo", tty="pts/0", ip_address="192.168.1.50")
		self.assertFalse(session.is_local())

	
	def test_is_local_returns_true(self):
		"""
			Testuje, czy metoda .is_local() poprawnie rozpoznaje sesję lokalną.
		"""
			
		session = TerminalSession(fail_type="sudo", tty="pts/0", ip_address=None)
		self.assertTrue(session.is_local())



if __name__ == '__main__':
	unittest.main()
