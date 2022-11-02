'''
Group 8
-------

Ben Hou(bh1760), Kyle Timmermans(kt2578), Devon Long(del9498), Priya Ganguly(pg2321)

Lab 7 - Test Cases
'''

import unittest
import socket

# Global Vars
incPort = 23457


'''
These 3 test cases test for the vulnerability in the incubator simulator
that allows for anyone to successfully send any command without a proper 
authentication token.
'''
class TestAdd(unittest.TestCase):

	# Simple string test token
	def test_case_1(self):
		try:
			s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
			s.sendto(b"AUTH foo;GET_TEMP", ("127.0.0.1", incPort))
			msg, addr = s.recvfrom(1024)
			msg = msg.decode("utf-8").replace('.', '').strip()
			s.close()

			# If this returns 'False', then the code has not been fixed
			self.assertEqual(msg.isdigit(), False)
		except Exception as e:
		    print(e)


	# 16 numbers test token
	def test_case_2(self):
		try:
			s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
			s.sendto(b"AUTH 111111111111111;GET_TEMP", ("127.0.0.1", incPort))
			msg, addr = s.recvfrom(1024)
			msg = msg.decode("utf-8").replace('.', '').strip()
			s.close()

			# If this returns 'False', then the code has not been fixed
			self.assertEqual(msg.isdigit(), False)
		except Exception as e:
		    print(e)


	# 16 symbols test token
	def test_case_3(self):
		try:
			s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
			s.sendto(b"AUTH !!!!!!!!!!!!!!!!;GET_TEMP", ("127.0.0.1", incPort))
			msg, addr = s.recvfrom(1024)
			msg = msg.decode("utf-8").replace('.', '').strip()
			s.close()

			# If this returns 'False', then the code has not been fixed
			self.assertEqual(msg.isdigit(), False)
		except Exception as e:
		    print(e)


if __name__ == '__main__':
	# If there are any failed test cases, then the code has not been fixed
    unittest.main()
