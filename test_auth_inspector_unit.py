import unittest
from unittest.mock import patch, MagicMock
import subprocess
import io

from auth_inspector import is_root


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



if __name__ == '__main__':
	unittest.main()
