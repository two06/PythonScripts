#!/usr/bin/env python
from scapy.all import *
import os
import ConfigParser
import time
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

#Globals
settings = ConfigParser.ConfigParser()
ap_list = []

def SendMail(APName, APMAC):
	msg = MIMEMultipart()
	fromAddress = settings.get('SMTP', 'FromAddress')
	ToAddress = settings.get('SMTP','ToAddress')
	msg['From'] = fromAddress
	msg['To'] = ToAddress
	msg['Subject'] = settings.get('SMTP','Subject')
	body = "Rogue AP SSID: %s MAC: %s detected!" %(APName, APMAC)
	msg.attach(MIMEText(body, 'plain'))

	server = smtplib.SMTP(settings.get('SMTP','server'), 587)
	server.ehlo()
	if(settings.get('SMTP', 'TlsEnabled') == 'true'):
		server.starttls()
		server.ehlo()
	server.login(settings.get('SMTP','username'), settings.get('SMTP','password'))
	server.sendmail(fromAddress, ToAddress, msg.as_string())		

def PacketHandler(pkt):
	white_list = settings.get('General','whiteList').split(',')
	white_list = map(str,white_list)
	if pkt.type ==0 and pkt.subtype == 8:
		if pkt.addr2 not in ap_list:
			ap_list.append(pkt.addr2)
			if pkt.info not in white_list:
				print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)
				SendMail(pkt.info, pkt.addr2)

def PrintHeader():
	print"             _           _                            _     "
	print" ___ _ _ ___| |_ ___ ___|_|___    ___ ___ ___ ___ _ _|_|___ "
	print"| -_| | | . |   | . |  _| |  _|  | . | -_|   | . | | | |   |"
	print"|___|___|  _|_|_|___|_| |_|___|  |  _|___|_|_|_  |___|_|_|_|"
	print"        |_|                      |_|         |___|          "
	print""
	print"Rogue AP detection"

def GetInterfaces():
	lst = []
	for l in open('/proc/net/dev'):
		if ':' in l:
			lst.append(l.split(':')[0].strip())
	return lst 

def main():
	PrintHeader()
	settings.read('config.ini')
	chans = settings.get('General', 'Channels').split(',')
	chans = map(int, chans)
	wait = float(settings.get('General','Delay')) 
	interface = settings.get('General','MonitorInterface')
	#check the interface exists
	ifList = GetInterfaces()
	if interface not in ifList:
		print 'Interface does not exist!'
		return

	i = 0
	while True:
		os.system('iwconfig %s channel %d' %(interface, chans[i]))
		print '%s channel set to %d' %(interface,chans[i])
		sniff(iface="mon0", prn = PacketHandler, count=int(settings.get('General','PacketCount')))
		i = (i+1) % len(chans)
		time.sleep(wait)

if __name__ == "__main__":
	main()