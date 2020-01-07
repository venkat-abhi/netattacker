from netattacker.attacker import AttackerBaseClass

class ScannerBaseClass(AttackerBaseClass):
	# 100 ports from nmap-services
	target_ports = [
		80, 23, 443, 21, 22, 25,
		3389, 110, 445, 139, 143, 53,
		135, 3306, 8080, 1723, 111, 995,
		993, 5900, 1025, 587, 8888, 199,
		1720, 465, 548, 113, 81, 6001,
		10000, 514, 5060, 179, 1026, 2000,
		8443, 8000, 32768, 554, 26, 1433,
		49152, 2001, 515, 8008, 49154, 1027,
		5666, 646, 5000, 5631, 631, 49153,
		8081, 2049, 88, 79, 5800, 106,
		2121, 1110, 49155, 6000, 513, 990,
		5357, 427, 49156, 543, 544, 5101,
		144, 7, 389, 8009, 3128, 444, 9999,
		5009, 7070, 5190, 3000, 5432, 1900,
		3986, 13, 1029, 9, 5051, 6646, 49157,
		1028, 873, 1755, 2717, 4899, 9100,
		119, 37
	]

	def __init__(self, target:str, target_ports:list=None, attack:str=None):
		"""
		Parameters
		----------
		target : str
			The target's hostname or IP address
		target_ports : list, optional
			User defined target ports
		attack : str
			Scan type being run on target

		"""
		super().__init__(target, attack=attack)

		if (target_ports is not None):
			self.target_ports = target_ports

		self.open_ports = []
		self.closed_ports = []
		self.filtered_ports = []
		self.unfiltered_ports = []
		self.open_filtered_ports = []
		self.closed_filtered_ports = []


	def print_target_ports(self):
		"""Prints the target ports"""
		print("[*] Target ports are:", *self.target_ports)

	def print_open_ports(self):
		"""Prints the ports found to be open"""
		if (self.open_ports):
			print("[*] The open ports are:", *self.open_ports)
		else:
			print("[#] No target ports found open")

	def print_closed_ports(self):
		"""Prints the ports found to be closed"""
		if (self.closed_ports):
			print("[*] The closed ports are:", *self.closed_ports)
		else:
			print("[#] No target ports found closed")

	def print_filtered_ports(self):
		"""Prints the ports found to be filtered"""
		if (self.filtered_ports):
			print("[*] The filtered ports are:", *self.filtered_ports)
		else:
			print("[#] No target ports found filtered")

	def print_unfiltered_ports(self):
		"""Prints the ports found unfiltered"""
		if (self.unfiltered_ports):
			print("[*] The unfiltered ports are:", *self.unfiltered_ports)
		else:
			print("[#] No target ports found unfiltered")

	def print_open_filtered_ports(self):
		"""Prints the ports found open|filtered"""
		if (self.open_filtered_ports):
			print("[*] The open|filtered ports are:", *self.open_filtered_ports)
		else:
			print("[#] No target ports found open|filtered")

	def print_closed_filtered_ports(self):
		"""Prints the ports found closed|filtered"""
		if (self.closed_filtered_ports):
			print("[*] The closed|filtered ports are:", *self.closed_filtered_ports)
		else:
			print("[#] No target ports found closed|filtered")
