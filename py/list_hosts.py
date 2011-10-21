#!/usr/bin/python

import xmlrpclib
import sys
import pprint
from optparse import OptionParser
import re

IPV4_ADDRESS_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def is_address(s):
	return IPV4_ADDRESS_REGEX.match(s) is not None
	
# default stuff -- could be made into options if you want
SERVER_URL = "http://127.0.0.1:55553"
USER = "msf"
PASSWORD = "abc123"

# parse command line options
parser = OptionParser(usage="Usage: %prog [options] [HOSTS]")
parser.add_option('-w', '--workspace', metavar='WORKSPACE', dest='workspace', help='specify workspace name to use', default=None)

(options, args) = parser.parse_args()

# Connect to server & authorize
proxy = xmlrpclib.ServerProxy(SERVER_URL)

ret = proxy.auth.login(USER, PASSWORD)
token = None
if ret['result'] == 'success':
	token = ret['token']
else:
	print "Could not login\n"
	sys.exit()
	
# Query all the data from the service
# This queries basically everything even if you only ask for one server
extra_args = []
if options.workspace is not None:
	extra_args = [options.workspace]
hosts = proxy.db.hosts(token, *extra_args)['hosts']
services = proxy.db.services(token, *extra_args)['services']
notes = proxy.db.notes(token, *extra_args)['notes']

# Figure out what hosts to query -- include anything whose name or address is in the positional arguments
hosts_to_list = hosts

args_set = set(arg.lower() for arg in args)

if len(args) > 0:
	hosts_to_list = []
	for h in hosts:
		if h['name'] and h['name'].lower() in args_set:
			hosts_to_list.append(h)
		elif h['address'] in args_set:
			hosts_to_list.append(h)
			
# Collect services by host
services_by_host = {}
for service in services:
	#print service
	services_by_host.setdefault(service['host'], []).append(service)
	
# Collect notes by host
notes_by_host = {}
for note in notes:
	if note['host']:
		notes_by_host.setdefault(note['host'],[]).append(note)

# Create a list of (host_addr_as_tuple, host)
# where host_addr_as_tuple is e.g. (192,168,1,1)
# for the purpose of sorting results
hosts_split = [(tuple(int(x) for x in h['address'].split('.')), h) for h in hosts_to_list]
hosts_split.sort()

# Print out all the results
for host_tuple, h in hosts_split:
	name = ''
	if h['name']:
		name = ' (%s)' % h['name']
	print '%s%s' % (h['address'], name)
	elements = []
	for s in services_by_host.get(h['address'], []):
		info = s['info'].strip()
		if info:
			info = '(%s)'%info
		s = '  Port %s %s: %s %s' % (s['port'],
								s['proto'].upper(),
								s['name'],
								info)
		elements.append(s)
	for n in notes_by_host.get(h['address'], []):
		s = '  Note: %s =\n    %s' % (n['type'], n['data'])
		elements.append(s)
	if elements:
		for e in elements:
			print e
	else:
		print '(No notes or ports)'
	print
