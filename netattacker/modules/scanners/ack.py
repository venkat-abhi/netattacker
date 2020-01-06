
from scapy.all import RandShort, sr, ICMP, IP, TCP

from netattacker.modules.scanners.scanner import ScannerBaseClass

class AckScanner(ScannerBaseClass):
	"""
	A class used to represent ACK based port scanner

	"""

	def __init__(self, target:str, target_ports:list=None, attack:str=None):
		super().__init__(target, target_ports=target_ports, attack="ACK_SCAN")
		self.unfiltered_ports = []

	def start(self, verbose:bool=False):
		print("[*] Starting ACK port scan")

		ip = IP(dst=self.target_ipv4)
		tcp = TCP(sport=RandShort(), dport=self.target_ports, flags="A")

		ans, unans = sr(ip/tcp, verbose=verbose, timeout=10)

		print("[*] ACK port scan complete")

		for s, r in ans:
			if (r.haslayer(TCP)):
				if (s[TCP].dport == r[TCP].sport):
					self.unfiltered_ports.append(s[TCP].dport)
			elif (r.haslayer(ICMP) and
				  r[ICMP].type == 3 and
				  r[ICMP].code in [1, 2, 3, 9, 10, 13]
				 ):
	 			self.filtered_ports.append(s[TCP].dport)

		for s in unans:
			print(s.show())
			self.filtered_ports.append(s[TCP].dport)

		if (verbose == True):
			AckScanner.print_unfiltered_ports(self)
			AckScanner.print_filtered_ports(self)

	def print_unfiltered_ports(self):
		print("[*] The unfiltered ports are:", *self.unfiltered_ports)

def main():
	a = AckScanner("www.amazon.com", target_ports=[80,443])
	print(a)
	a.start()
	a.print_unfiltered_ports()

	b = AckScanner("www.yahoo.com")
	b.print_target_ports()
	b.start(verbose=True)

if __name__ == "__main__":
	main()