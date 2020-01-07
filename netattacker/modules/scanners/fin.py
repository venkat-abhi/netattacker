from scapy.all import RandShort, sr, ICMP, IP, TCP

from netattacker.modules.scanners.scanner import ScannerBaseClass

class FinScanner(ScannerBaseClass):
	"""
	A class used to represent TCP FIN based port scanner

	...

	Attributes
	----------
	target : str
		The target's hostname or IP address
	target_ports : list
		The ports to which the FIN will be sent to (default - target_ports)

	Methods
	-------
	start()
		Creates FIN packets and sends them to scan the target

	"""

	def __init__(self, target:str, target_ports:list=None):
		super().__init__(target, target_ports=target_ports, attack="FIN_SCAN")

	def start(self, verbose:bool=False):
		"""
		Scans the ports and stores the results in a list; If verbose flag is passed,
		the output is printed as well.
		"""
		print("[*] Starting FIN port scan")

		ip = IP(dst=self.target_ipv4)
		tcp = TCP(sport=RandShort(), dport=self.target_ports, flags="F")

		ans, unans = sr(ip/tcp, verbose=verbose, timeout=10)

		print("[*] FIN port scan complete")

		for s in unans:
			self.open_filtered_ports.append(s[TCP].dport)

		for s, r in ans:
			if (r.haslayer(TCP)):
				# Following nmap convention (both RST, RST/ACK)
				if (r[TCP].flags & 0x16 in [0x4, 0x14]):
					self.closed_ports.append(s[TCP].dport)
			elif (r.haslayer(ICMP) and
				  r[ICMP].type == 3 and
				  r[ICMP].code in [1, 2, 3, 9, 10, 13]
				 ):
	 			self.filtered_ports.append(s[TCP].dport)

		if (verbose == True):
			FinScanner.print_closed_ports(self)
			FinScanner.print_filtered_ports(self)
			FinScanner.print_open_filtered_ports(self)



def main():
	a = FinScanner("www.amazon.com", target_ports=[80,443])
	print(a)
	a.start()
	a.print_unfiltered_ports()

	b = FinScanner("www.yahoo.com")
	b.print_target_ports()
	b.start(verbose=True)

if __name__ == "__main__":
	main()