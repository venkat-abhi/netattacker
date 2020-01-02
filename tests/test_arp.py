import netattacker as sm

class TestAttacker:
	def test_arp_init(self, capsys):
		arp_instance = sm.grab('poisoners.arp', target='192.168.1.2')

		arp_instance.print_target_ip()

def main():
	a = TestAttacker()
	a.test_arp_init('test')

if __name__ == "__main__":
	main()