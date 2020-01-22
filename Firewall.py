import csv
from collections import namedtuple
IPRange = namedtuple("IPRange", ("ip_start", "ip_end"))

class Firewall:
    def __init__(self, path):
        self.path = path
        self.traffic = {}
        self.load_from_csv()

    def load_from_csv(self):
        try:
            with open(self.path, 'r') as csvfile:
                csvreader = csv.reader(csvfile)
                for row in csvreader:
                    direction = row[0]
                    protocol = row[1]
                    ip = row[3]
                    port = row[2]
                    ip_range = ip.strip().split("-")
                    ip_start = ip_range[0].strip()
                    ip_end = ip_range[1].strip() if len(ip_range) == 2 else ip_start

                    port_range = port.strip().split("-")
                    start_port = port_range[0]
                    end_port = port_range[1] if len(port_range) == 2 else start_port

                    iprange = IPRange(ip_start, ip_end)

                    for port in range(int(start_port), int(end_port) + 1):
                        traffic_type = self.get_key(direction, protocol, port)
                        if traffic_type not in self.traffic.keys():
                            self.traffic[traffic_type] = [iprange]
                        else:
                            self.traffic[traffic_type].append(iprange)
        except Exception as e:
            print('Exception ' + str(e))


    def get_key(self, direction, traffic, port):
        """
        Using a hash to store ip address range, based on input of half a million entries, and average fanout
        i found it better and simple for time given to key based on direction, protocol, and port
        we are storing all the  ip ranges, optimization can be done by merging ip ranges.
        """
        return direction + '_' + traffic + '_' + str(port)

    def is_valid_range(self, start_ip, end_ip, ipaddr):
        """
        For ip adddress range comparison, converting ip address to int for easy comparison
        It can be optimized.
        """
        start, end, cur = start_ip.split("."), end_ip.split("."), ipaddr.split(".")

        start_int = int(start[0]) * pow(256, 3) + int(start[1]) * pow(256, 2) + int(start[2])*256 + int(start[3])
        end_int = int(end[0])*pow(256, 3) + int(end[1]) * pow(256, 2) + int(end[2])*256 + int(end[3])
        cur_int = int(cur[0]) * pow(256, 3) + int(cur[1]) * pow(256, 2) + int(cur[2]) * 256 + int(cur[3])

        if cur_int <= end_int and cur_int >= start_int:
            return True
        return False

    def accept_packet(self, direction, protocol, port, ipaddr):
        key = self.get_key(direction, protocol, port)

        allowed_list = self.traffic.get(key)
        if not allowed_list:
            return False

        for iprange in allowed_list:
            if self.is_valid_range(iprange.ip_start, iprange.ip_end, ipaddr):
                return True
        return False