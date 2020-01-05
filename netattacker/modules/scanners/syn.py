from scapy.all import IP, RandShort, sr, TCP

from netattacker.attacker import AttackerBaseClass

class SynScanner(AttackerBaseClass):

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

	def __init__(self, target:str, target_ports:list=None):
		super().__init__(target, attack="ARP_SCAN")

		if (target_ports is not None):
			self.target_ports = target_ports

		self.open_ports = []

	def print_target_ports(self):
		"""Prints the ports to which the SYN packets will be sent."""
		print("[*] Target ports are:", *self.target_ports)

	def print_open_ports(self):
		print("[*] The open ports are:", *self.open_ports)

	def start(self, verbose:bool=False):
		"""
			Scans the ports and stores the results in a list; If verbose flag is passed,
			the output is printed as well
		"""

		print("[*] Starting SYN port scan")

		ip = IP(dst=self.target_ipv4)
		tcp = TCP(sport=RandShort(), dport=self.target_ports, flags="S")

		ans, unans = sr(ip/tcp, verbose=verbose, timeout=10)

		print("[*] SYN scan complete")

		for i in ans:
			if ("SA" == i[1][1].flags):
				self.open_ports.append(i[1][1].sport)

		if (verbose == True):
			SynScanner.print_open_ports(self)

def main():
	a = SynScanner("www.google.com", target_ports=[80,443])
	print(a)
	a.print_target_ports()
	a.start(verbose=True)

	b = SynScanner("www.yahoo.com")
	print(b)
	b.start()
	b.print_open_ports()

if __name__ == "__main__":
	main()