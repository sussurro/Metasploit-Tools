#!/usr/bin/python

import xmlrpclib
import sys
from optparse import OptionParser

# parse command line options
parser = OptionParser(usage="Usage: %prog [options] [HOSTS]")
parser.add_option('-w', '--workspace', metavar='WORKSPACE', dest='workspace', help='specify workspace name to use', default=None)
parser.add_option('-t', '--target', metavar='TARGET', dest='target', help='secify target host to search for', default=None)
parser.add_option('-x', '--xurl', metavar='XURL', dest='xurl', help='xmlrpc server location', default="http://127.0.0.1:55553/RPC2")
parser.add_option('-u', '--user', metavar='USER', dest='user', help='xmlrpc username', default="msf")
parser.add_option('-p', '--pass', metavar='PASS', dest='password', help='xmlrpc password', default=None)

(options, args) = parser.parse_args()
SERVER_URL = options.xurl
USER = options.user
PASSWORD = options.password

# Connect to server & authorize
proxy = xmlrpclib.ServerProxy(SERVER_URL)

ret = proxy.auth.login(USER, PASSWORD)
token = None
if ret['result'] == 'success':
	token = ret['token']
else:
	print "Could not login\n"
	sys.exit()

if options.target is None:
	print "You must specify a target to search for\n"
	sys.exit()
	
# Query all the data from the service
# This queries basically everything even if you only ask for one server
extra_args = {}
workspace = ""
if options.workspace is not None:
	extra_args['workspace'] = [options.workspace]
	workspace = options.workspace
extra_args['ponies'] = "monkies"
extra_args['host'] = options.target

hosts = proxy.db.get_host(token,extra_args)
services = proxy.db.get_service(token,extra_args)

notes = proxy.db.get_note(token, extra_args)
vulns = proxy.db.get_vuln(token, extra_args)

host = hosts['host'][0]

print("Host report for %s (v4: %s, v6: %s) Status: %s") % ((host['name'] if host['name'] else "Unknown") ,host['address'],host['address6'],host['state'] if host['state'] else "Unknown")
print("\tFirst Discovered: %-20s, Last Discovered: %s") % (host['created_at'],host['updated_at'])
print("\tOS: %s %s %s %s\tMac: %s") % ( host['os_name'], host['os_sp'], host['os_lang'], host['os_flavor'], host['mac'])
print("\tPurpose: %s\n\tInfo: %s") % (host['purpose'], host['info'])
print("\nServices:\n")

print("\t%10s\t%10s\t%s") %("Port","State","Information")
print "\t" + "-"*48
for s in services['service']:
	print("\t%10s\t%10s\t%s") %(str(s['port']) + "/" + s['proto'],s["state"],s["name"] + " : " + s["info"])

print "\nVulnerabilities:"
for v in vulns['vuln']:
	print "\t" + "-"*48
	print("\tPort: %10s\t Ref: %s") % (str(v['port']) + "/" + v['proto'], ",".join(v['refs']))
	print "\tName: %s" % v['name']
	print "\tInfo: %s" % v['info']
	print "\tFirst seen: %20s\t Last seen: %20s\n" % (v['created_at'],v['updated_at'])

print "\nNotes:"
for n in notes['note']:
	port = "Unknown"
	if n.has_key('port'):
		port = n['port'] + "/" + n['proto']
	print "\t" + "-"*48
	print("\tNote Type: %s , Port: %s") % (n['ntype'], port)
	print "\tFirst seen: %20s\t Last seen: %20s" % (n['created_at'],n['updated_at'])
	print "\tCritical: %20s\t Seen: %20s" % (n['critical'],n['seen'])
	print "\tData:"
	if n['data'] and type(n['data']) is dict:
		for k,v in n['data'].items():
			print "\t\t%s => %s" % (k,v)
 	
