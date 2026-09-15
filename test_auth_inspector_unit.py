import unittest
from unittest.mock import patch, MagicMock
import subprocess
import io

from auth_inspector import TerminalSession, on_startup


class TestTerminalSession(unittest.TestCase):


	fake_who_output = "root     pts/2        2026-09-08 13:37\nprezes   sshd pts/1   2026-09-08 13:35 (192.168.1.104)\nprezes   sshd pts/0   2026-09-08 11:29 (192.168.1.104)"


	def test_get_tty_valid_return(self):
		""" 
			Tests if the function gets TTY from a systemd log properly.
		"""

		session = TerminalSession(fail_type="", tty=None, ip_address=None)

		log_line = "pam_unix(sudo:auth): authentication failure; tty=/dev/pts/2 user=prezes"
		result = session._extract_tty(log_line)
		self.assertEqual(result, "pts/2")


	@patch('subprocess.run')
	def test_get_ip_vaild_return(self, mock_run):
		""" 
			Tests if the function gets IP from the who command properly.
		"""

		mock_response = MagicMock()
		mock_response.stdout = __class__.fake_who_output
		mock_run.return_value = mock_response

		session = TerminalSession(fail_type="", tty=None, ip_address=None)

		ip = session._fetch_ip_from_system("pts/1")
		self.assertEqual(ip, "192.168.1.104")


	def test_is_local_returns_false(self):
		"""
			Tests if the .is_local() method properly recognizes a ssh session.
		"""

		session = TerminalSession(fail_type="sudo", tty="pts/0", ip_address="192.168.1.50")
		self.assertFalse(session.is_local())

	
	def test_is_local_returns_true(self):
		"""
			Tests if the .is_local() method properly recognizes a local session.
		"""
			
		session = TerminalSession(fail_type="sudo", tty="pts/0", ip_address=None)
		self.assertTrue(session.is_local())


	@patch("os.geteuid", create=True)
	def test_startup_permmision_check(self, mock_geteuid):
		"""
			Tests if the starup function detects lack of root permisions correctly.
		"""

		mock_geteuid.return_value = 1000 # <-- simulates lack of permissions

		with self.assertRaises(SystemExit) as context:
			on_startup()

		self.assertEqual(
			context.exception.code, 1,
			"Error: The program did not detect lack of permissions during the test."
		)


	@patch("os.geteuid", create=True)
	@patch("sys.stderr", new_callable=io.StringIO)
	def test_startup_permmision_check_messsage(self, mock_stderr, mock_geteuid):
		"""
			Tests if the startup function prints the message
			about lack of permissions properly.
		"""
	
		mock_geteuid.return_value = 1000 # <-- simulates lack of permissions
	
		with self.assertRaises(SystemExit):
			on_startup()
	
		printed_output = mock_stderr.getvalue()

		self.assertIn(
			"[Auth-inspector] Error: Please run the script as root.", 
			printed_output, 
			(
				"Error: The program stopped working(as intended) but did not "
				"display a clear message about the lack of permissions problem."
			)
		)



if __name__ == '__main__':
	unittest.main()
