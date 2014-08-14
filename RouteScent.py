'''
things need to grab automatically

client mac
initial start packets

switch mac
gw mac
gw ip 
client ip

dhcp - will contain the gw IP - potentially the MAC
nat-pmp
kerberos
smb
igmpv2 - gw sends out general query

detect arp packets - responses

compare with udp/tcp/icmp packets containing the same mac

gwmac = ""
gwip = ""
iptable = {}
arptable = {}
'''

def dhcp_pkt(pkt):
	global iptable, arptable, gwmac, gwip
	gwip = pkt.gwip
	
	print "Gateway IP " + gwip + "found through DHCP response"
	
	try:
		gwmac = iptable[gwip]
		
		print "Gateway MAC " + gwmac + "found through DHCP "
		
	except:
		pass

	
def ip_pkt(pkt):
	global iptable, arptable, gwmac, gwip
	iptable[pkt.srcip] = pkt.srcmac
	iptable[pkt.dstip] = pkt.dstmac

	# search IP tables for multiple entries of same MAC
	
	for ip, mac in iptable:
		if ((mac == pkt.srcmac) and (ip != pkt.srcip)) or \
			((mac == pkt.dstmac) and (ip != pkt.dstip)):
			gwmac = mac
			
		
	if pkt.srcmac in arp_tables:
		if pkt.srcip != arp_table[pkt.srcmac]:
			gwip = arp+table[pkt.srcmac]

	if pkt.dstmac in arp_tables:
			if pkt.dstip != arp_table[pkt.dstmac]:
				gwip = arp+table[pkt.dstmac]
	

def arp_pkt(pkt):
	global iptable, arptable, gwmac, gwip	
	
	arptable[pkt.srcmac] = pkt.srcip
	iptable[pkt.srcip] = pkt.srcmac

	def pkt_process(pkt)

	if pkt.type() == dhcp:

		dhcp_pkt(pkt)
		
	else if:
		
		arp_pkt(pkt)
		
	else if:

		ip_pkt(pkt)
		
	else if:

		igmp_pkt(pkt)
		

while (gwip == "") and (gwmac == "")