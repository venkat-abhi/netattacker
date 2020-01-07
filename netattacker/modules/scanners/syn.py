from scapy.all import IP, RandShort, sr, TCP

from netattacker.modules.scanners.scanner import ScannerBaseClass

class SynScanner(ScannerBaseClass):
	"""
	A class used to represent a SYN port scanner

	...

	Attributes
	----------
	target : str
		The target's hostname or IP address
	target_ports : list
		The ports to which the SYNs will be sent to (default - target_ports)

	Methods
	-------
	start()
		Creates SYN packets and sends them to scan the target
	"""
	def __init__(self, target:str, target_ports:list=None):
		super().__init__(target, target_ports=target_ports, attack="SYN_SCAN")

	def start(self, verbose:bool=False):
		"""
		Scans the ports and stores the results in a list; If verbose flag is passed,
		the output is printed as well.
		"""
		print("[*] Starting SYN port scan")

		ip = IP(dst=self.target_ipv4)
		tcp = TCP(sport=RandShort(), dport=self.target_ports, flags="S")

		ans, unans = sr(ip/tcp, verbose=verbose, timeout=10)

		print("[*] SYN scan complete")

		for s, r in ans:
			if ("SA" == r[TCP].flags):
				self.open_ports.append(r[TCP].sport)

		for s in unans:
			self.filtered_ports.append(s[TCP].dport)

		if (verbose == True):
			SynScanner.print_open_ports(self)
			SynScanner.print_filtered_ports(self)

def main():
	a = SynScanner("www.amazon.com", target_ports=[80,443])
	print(a)
	a.print_target_ports()
	a.start()
	a.print_open_ports()

	b = SynScanner("www.yahoo.com")
	b.print_target_ports()
	b.start(verbose=True)

if __name__ == "__main__":
	main()