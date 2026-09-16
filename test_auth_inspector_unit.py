import unittest
from unittest.mock import patch, MagicMock
import subprocess
import io

from auth_inspector import Action, is_root, parse_audit_message, on_log_line_recieve


class TestTerminalSession(unittest.TestCase):

	@patch("os.geteuid", create=True)
	def test_startup_permmision_check(self, mock_geteuid):
		"""
			Tests if the .is_root() function detects lack of root permisions correctly.
		"""

		mock_geteuid.return_value = 1000 # <-- simulates lack of permissions
		result = is_root()

		self.assertEqual(
			result, False,
			"Error: The program did not detect lack of permissions during the test."
		)

	def test_valid_message_parsing(self):
		"""
			Tests if the .parse_audit_message() function returns properly formated
			message(in the case of a valid message).
		"""

		raw_msg = """type=CRED_ACQ msg=audit(1789554012.232:957): pid=17451 uid=0 auid=1000 ses=12 subj=unconfined msg='op=PAM:setcred grantors=pam_permit acct="sas" exe="/usr/lib/openssh/sshd-session" hostname=192.168.1.67 addr=192.168.1.67 terminal=ssh res=success' UID="root" AUID="sas" """
		result = parse_audit_message(raw_msg)

		self.assertEqual(result["addr"], "192.168.1.67")
		self.assertEqual(result["ses"], "12")
		self.assertEqual(result["type"], "CRED_ACQ")
		self.assertEqual(result["res"], "success")
		self.assertEqual(result["exe"], "/usr/lib/openssh/sshd-session")
		self.assertEqual(result["AUID"], "sas")

	def test_invalid_message_parsing(self):
		"""
			Tests if the .parse_audit_message() function returns properly formated
			message(in the case of a invalid message).
		"""
	
		raw_msg = """type=CRED_ACQ msg=audit(1789554012.212:954): pid=17444 uid=0 auid=4294967295 ses=4294967295 subj=unconfined msg='op=PAM:setcred grantors=pam_permit acct="sas" exe="/usr/lib/openssh/sshd-session" hostname=192.168.1.67 addr=192.168.1.67 terminal=ssh res=success' UID="root" AUID="unset" """
		result = parse_audit_message(raw_msg)
	
		self.assertEqual(result["AUID"], "unset")

	def test_enum_unknown_value(self):
		"""
			Test if the enum behaviour on unwanted action type is handled
			as intended.
		"""

		action_type = Action("CRED_SAS")
		self.assertEqual(action_type, Action.UNKNOWN)

	def test_ssh_connection_detection(self):
		"""
			Tests if the program registers the data
			of established ssh connection properly.
		"""

		logged_action = {
			"addr": "192.168.1.67",
			"ses": "12",
			"type": "CRED_ACQ",
			"res": "succes",
			"AUID": "sas"
		}

		session_to_ip = {}
		on_log_line_recieve(logged_action, session_to_ip)

		self.assertTrue(session_to_ip)
		self.assertEqual(session_to_ip["12"], "192.168.1.67")

	def test_ssh_connection_detection_filter(self):
		"""
			Tests if the program can recongize 
			an unnescesary entry.
		"""
	
		logged_action_invalid = {
			"addr": "192.168.1.67",
			"ses": "456775345",
			"type": "CRED_ACQ",
			"res": "succes",
			"AUID": "unset"
		}
	
		session_to_ip = {}
		on_log_line_recieve(logged_action_invalid, session_to_ip)
	
		self.assertFalse(session_to_ip)

	def test_ssh_disconnection_detection(self):
		"""
			Tests if the program deletes the data of
			a once registered connection which now
			disconnected.
		"""

		logged_action = {
			"type": "CRED_DISP",
			"ses": "420"
		}

		session_to_ip = {"420": "192.168.1.67", "421": "192.168.1.69"}
		on_log_line_recieve(logged_action, session_to_ip)

		self.assertEqual(len(session_to_ip), 1)
		self.assertNotIn("420", session_to_ip)
		




if __name__ == '__main__':
	unittest.main()
