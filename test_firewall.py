from Firewall import Firewall
import unittest

class TestFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.firewall = Firewall("./NetworkRules.csv")

    def test_allowed(self):
        assert self.firewall.accept_packet("outbound", "tcp", 1500, "192.169.1.1") == True
        assert self.firewall.accept_packet("inbound", "udp", 166, "192.168.1.2")== True
        assert self.firewall.accept_packet("outbound", "udp", 115, "182.183.184.185") == True
        assert self.firewall.accept_packet("inbound", "udp", 175, "10.11.12.10") == True

    def test_blocked(self):
        assert self.firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2")== False
        assert self.firewall.accept_packet("outbound", "udp", 80, "12.34.6.25") == False
        assert self.firewall.accept_packet("inbound", "tcp", 26, "123.45.56.83")== False
        assert self.firewall.accept_packet("inbound", "tcp", 125, "11.11.11.11") == False
        assert self.firewall.accept_packet("outbound", "tcp", 20000, "200.200.200.201") == False
        assert self.firewall.accept_packet("inbound", "udp", 175, "10.11.12.9") == False
        assert self.firewall.accept_packet("inbound", "udp", 259, "10.11.12.13") == False


if __name__ == '__main__':
    unittest.main()
