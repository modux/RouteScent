#!/usr/bin/python

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
'''
from scapy.all import *
import argparse

class RouteScent():
  
  def __init__(self):
  
    self.gwmac = ""
    self.gwip = ""
    self.iptable = {}
    self.arptable = {}
    self.ttls=[64,128,32,60,255]  
  
  def dhcp_pkt(self,pkt):
    
        
    print "Gateway IP " + gwip + "found through DHCP response"
    
    try:
      gwmac = iptable[gwip]
      
      print "Gateway MAC " + gwmac + "found through DHCP "
      
    except:
      pass
  
    
  def ip_pkt(self,pkt):
    
    
    self.iptable[pkt[IP].src] = pkt.src
    self.iptable[pkt[IP].dst] = pkt.dst
    
    self.arptable[pkt.src]=pkt[IP].src
    self.arptable[pkt.dst]=pkt[IP].dst
    # search IP tables for multiple entries of same MAC
    print pkt.ttl     
    for ip, mac in self.iptable.items():
      if ((mac == pkt.src) and (ip != pkt[IP].src)):
        self.gwmac = mac
        print "GW MAC!!" + self.gwmac
        if pkt.ttl in self.ttls:
          print "GW IP" + pkt[IP].src
      if ((mac == pkt.dst) and (ip != pkt[IP].dst)):
        self.gwmac = mac
        print "GW MAC!!" + self.gwmac
        
    
    if pkt.src in self.arptable and \
       pkt[IP].src != self.arptable[pkt.src]:
        self.gwip = self.arptable[pkt.src]
        print self.gwip
    if pkt.dst in self.arptable and \
       pkt[IP].dst != self.arptable[pkt.dst]:
          self.gwip = self.arptable[pkt.dst]
    if self.gwip is not "":
      print "GW found through analysis!" + self.gwip
  
  def arp_pkt(self,pkt):
      
    
    self.arptable[pkt.srcmac] = pkt.srcip
    self.iptable[pkt.srcip] = pkt.srcmac
  
  def process_pkt(self,pkt):
  
    if pkt.haslayer(DHCP):

      self.dhcp_pkt(pkt)
      
    elif pkt.haslayer(IP):    
      self.ip_pkt(pkt)
      
    #elif pkt.type== ip:
  
     # ip_pkt(pkt)
      
    #elif pkt.type==igmp:
  
    #  igmp_pkt(pkt)
      
  
  def threaded_sniff_target(self):
           
    conf.iface=self.iface
          
    sniff(prn = lambda x : self.process_pkt(x))
 
  def read_file(self,file):

    pkts=rdpcap(file)
    for p in pkts:
      self.process_pkt(p)
       
def main():
  parser = argparse.ArgumentParser(description="Network SED for on the wire find and replace", usage="./RouteScent.py [-i eth0] [-f filename] [options]")


  parser.add_argument('-i',"--interface",dest="iface", metavar='REGEX',type=str,help="Interface to smell on")
  parser.add_argument('-f', '--file',metavar='Pcap',type=str,help='PCAP file to read')
  
  args=parser.parse_args()
  

  rs=RouteScent()
  
  if args.iface:
    
    rs.iface=args.iface
    rs.threaded_sniff_target()
  elif args.file:
    
    rs.read_file(args.file)  

  while 1:
    pass
#  while (gwip == "") and (gwmac == ""):
 #   print



if __name__=="__main__":
    main()


