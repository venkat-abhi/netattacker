import netattacker as sm

class TestAttacker:
	def test_arp_init(self, capsys):
		arp_instance = sm.grab('poisoners.arp', target='192.168.1.2')

		arp_instance.print_target_ip()

		dns_hijacker = sm.grab('poisoners.dns', target='192.168.1.2', webserver_ipv4='192.168.1.4')
		dns_hijacker.start()

def main():
	a = TestAttacker()
	a.test_arp_init('test')

if __name__ == "__main__":
	main()