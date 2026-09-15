import unittest
import subprocess
import shutil
import os
from auth_inspector import TerminalSession, log_incident, on_startup, LOG_DIR, LOG_FILE


class TestTerminalSessionIntegration(unittest.TestCase):


	def remove_logs(self):
		"""
			Deletes files created during at runtime.
		"""

		if os.path.exists(LOG_DIR):
			shutil.rmtree(LOG_DIR)

	def setUp(self):
		"""
			Preparation before each test.
		"""

		self.remove_logs()

	def tearDown(self):
		"""
			Cleanup after each test.
		"""

		self.remove_logs()

	def test_with_who_command(self):
		"""
			Tests if the program works properly with the who command.
		"""
		try:
			result = subprocess.run(['who'], capture_output=True, text=True, check=True)
			print(f"\n[INFO] WHO output:\n{result.stdout}")
			
		except (subprocess.SubprocessError, FileNotFoundError) as e:
			self.fail(f"Integration test failed, WHO command not found! Error: {e}")

	def test_search_non_existent_terminal(self):
		"""
			Tests if the program reacts properly to a situation in which
			it searches for a terminal which does not exist in the active sessions.
		"""
		
		with self.assertRaises(LookupError) as context:
			TerminalSession._fetch_ip_from_system("fake/terminal/999")# <-- will not be found be the who command
			
		self.assertIn("[Auth-inspector] Terminal", str(context.exception))


	def test_log_directory_creation(self):
		"""
			Checks if the nonexistent logs folder was created by the program.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program existed before the test and it should not."
		)

		on_startup()

		self.assertTrue(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program was not created despite it did not exist before."
		)
		

	def test_log_saving(self):
		"""
			Checks if the nonexistent log file was created by the program.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program existed before the test and it should not."
		)

		on_startup()
		log_incident(TerminalSession("sudo", "pts/1", "192.168.1.104"))

		self.assertTrue(
			os.path.exists(LOG_DIR), 
			f"Error: The log file was not created in the path {LOG_DIR}"
		)


	def test_log_saved_content(self):
		"""
			Tests if the content of a singular line of the log file is valid.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program existed before the test and it should not."
		)

		session = TerminalSession("sudo", "pts/1", "192.168.1.104")

		on_startup()
		log_incident(session)

		with open(LOG_FILE, "r") as f:
			file_content = f.read()
		
		self.assertIn("SUDO", session.fail_type, "Error: The program does not save the information about failed auth type properly.")
		self.assertIn("pts/1", session.tty, "Error: The Program does not save the information about the TTY properly.")
		self.assertIn("192.168.1.1", session.ip_address, "Error: The Program does not save the information about the IP properly.")


	def test_log_saving_line_count(self):
		"""
			Tests if one call of the .log_incident() corresponds
			to exactly one saved line in the log file.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program existed before the test and it should not."
		)
		
		session = TerminalSession("sudo", "pts/1", "192.168.1.104")
		on_startup()

		for i in range(2):
			log_incident(session)
			
			with open(LOG_FILE, "r") as f:
				line_count = len(f.readlines())

			self.assertEqual(line_count, i + 1)
