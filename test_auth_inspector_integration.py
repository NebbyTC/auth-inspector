import unittest
import threading
import time
import shutil
import os

from systemd import journal 

from auth_inspector import log_incident, on_startup, on_log_line_recieve, open_system_logs, run, LOG_DIR, LOG_FILE



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
		log_incident("sudo", "192.168.1.67")

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

		on_startup()
		FAIL_TYPE = "sudo"
		IP_ADDRESS = "192.168.1.67"
		log_incident(FAIL_TYPE, IP_ADDRESS)

		with open(LOG_FILE, "r") as f:
			file_content = f.read()
		
		self.assertIn(FAIL_TYPE, file_content, "Error: The program does not save the information about failed auth type properly.")
		self.assertIn(IP_ADDRESS, file_content, "Error: The Program does not save the information about the IP properly.")


	def test_log_saving_line_count(self):
		"""
			Tests if one call of the .log_incident() corresponds
			to exactly one saved line in the log file.
		"""

		self.assertFalse(
			os.path.exists(LOG_DIR), 
			f"Error: The logs folder({LOG_DIR}) of the program existed before the test and it should not."
		)
		
		on_startup()

		for i in range(2):
			log_incident("sudo", "192.168.1.67")
			
			with open(LOG_FILE, "r") as f:
				line_count = len(f.readlines())

			self.assertEqual(line_count, i + 1)


	def test_auth_atempt_fail_detection(self):
		"""
			Tests if the program properly responds 
			to a mock failed auth attempt.
		"""

		logged_action = {
			"type": "USER_AUTH",
			"res": "failed",
			"exe": "/usr/bin/sudo",
			"ses": "420"
		}
		
		session_to_ip = {"420": "192.168.1.67", "421": "192.168.1.69"}

		on_startup()
		on_log_line_recieve(logged_action, session_to_ip)

		with open(LOG_FILE, "r") as f:
			file_content = f.read()
		
		self.assertIn("/usr/bin/sudo", file_content, "Error: The program does not save the information about failed auth type properly.")
		self.assertIn("192.168.1.67", file_content, "Error: The Program does not save the information about the IP properly.")

	def test_context_manager_wakes_up_correctly_on_live_event(self):
		"""
			Tests that the audit_journal_context opens successfully, 
			and reader.wait() correctly handles a live systemd message 
			injected via journal.send().
		"""

		inspector_thread = threading.Thread(target=run, daemon=True)
		inspector_thread.start()
		
		time.sleep(1.0)

		journal.send(
			MESSAGE='type=CRED_ACQ msg=audit(1789554012.232:957): pid=17451 uid=0 auid=1000 ses=88 acct="prezes" exe="/usr/lib/openssh/sshd-session" addr=192.168.1.55 AUID="prezes"',
			SYSLOG_IDENTIFIER='audisp-syslog'
		)
		time.sleep(0.1)
		journal.send(
			MESSAGE='type=USER_AUTH msg=audit(1789554015.555:958): pid=17460 uid=0 auid=1000 ses=88 acct="root" exe="/usr/bin/sudo" res=failed',
			SYSLOG_IDENTIFIER='audisp-syslog'
		)

		time.sleep(5)
		
		self.assertTrue(os.path.exists(LOG_FILE), "Error: Log file was not created!")
		
		with open(LOG_FILE, "r") as f:
			log_content = f.read()

		self.assertIn("auth-inspector: Failed /usr/bin/sudo auth attempt from IP=192.168.1.55", log_content)

