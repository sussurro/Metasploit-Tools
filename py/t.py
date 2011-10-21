#!/usr/bin/python

import xmlrpclib
import sys
import pprint
import time

# default stuff -- could be made into options if you want
SERVER_URL = "http://127.0.0.1:55553"
USER = "msf"
PASSWORD = "abc123"

proxy = xmlrpclib.ServerProxy(SERVER_URL)


#Login Check
sys.stdout.write("Attempting Login: ")
ret = proxy.auth.login(USER, PASSWORD)
token = None
if ret['result'] == 'success':
	token = ret['token']
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#Report Host Check
sys.stdout.write("Attempting To add Hosts: ")
extra_opts = {}	
extra_opts['host'] = "192.168.1.1"
ret = proxy.db.report_host(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)

#Hosts command check
sys.stdout.write("Verifying Add Through Hosts Command: ")
extra_opts = {}	
extra_opts['addresses'] = ['192.168.1.1']
ret = proxy.db.hosts(token,extra_opts)
if ret['hosts'] and len(ret['hosts']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#get_host check
sys.stdout.write("Verifying Add Through Get_Host check: ")
extra_opts = {}	
extra_opts['host'] = '192.168.1.1'
ret = proxy.db.get_host(token,extra_opts)
if ret['host'] and len(ret['host']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#Add Service Check
sys.stdout.write("Testing Report Service: ")
extra_opts = {}	
extra_opts['host'] = '192.168.1.1'
extra_opts['port'] = 445
extra_opts['proto'] = "tcp"
ret = proxy.db.report_service(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)

#Check if service was added
sys.stdout.write("Verifying Add Through Services cmd: ")
ret = proxy.db.services(token,extra_opts)
if ret['services'] and len(ret['services']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
#Check if service was added
sys.stdout.write("Verifying Add Through Get_Service: ")
ret = proxy.db.get_service(token,extra_opts)
if ret['service'] and len(ret['service']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#Add a note:
sys.stdout.write("Adding a new note to service: ")
extra_opts['ntype'] = "tnote"
extra_opts['data'] = { "ponies" : "puppies" }
ret = proxy.db.report_note(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)

del extra_opts['data']

#verify add
sys.stdout.write("Verifying Add Through Notes cmd: ")
ret = proxy.db.notes(token,extra_opts)
if ret['notes'] and len(ret['notes']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#verify add
sys.stdout.write("Verifying Add Through get_note: ")
ret = proxy.db.get_note(token,extra_opts)
if ret['note'] and len(ret['note']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#test without a service, host only
sys.stdout.write("Adding a new note to host: ")
del extra_opts['port']
del extra_opts['proto']
extra_opts['host'] = '192.168.1.2'
extra_opts['data'] = { "ponies" : "puppies" }
ret = proxy.db.report_note(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)

del extra_opts['data']
#verify add
sys.stdout.write("Verifying Add Through Notes cmd: ")
ret = proxy.db.notes(token,extra_opts)
if ret['notes'] and len(ret['notes']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#verify add
sys.stdout.write("Verifying Add Through get_note: ")
ret = proxy.db.get_note(token,extra_opts)
if ret['note'] and len(ret['note']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#Add Vuln check
sys.stdout.write("Testing Report Vuln: ")
extra_opts = {}	
extra_opts['host'] = '192.168.1.1'
extra_opts['port'] = 445
extra_opts['proto'] = "tcp"
extra_opts['refs'] = ['SUS_1234','SUS_5678']
extra_opts['info'] = "This is a test vulnerability"
extra_opts['name'] = "TestVuln1"

ret = proxy.db.report_vuln(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)


del extra_opts['info']
del extra_opts['refs']

#verify add
sys.stdout.write("Verifying Add Through vulns: ")
ret = proxy.db.vulns(token,extra_opts)
if ret['vulns'] and len(ret['vulns']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#verify add
sys.stdout.write("Verifying Add Through get_vuln: ")
ret = proxy.db.get_vuln(token,extra_opts)
if ret['vuln'] and len(ret['vuln']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#Add Client Check
sys.stdout.write("Testing Report Client: ")
extra_opts = {}	
extra_opts['host'] = '192.168.1.1'
extra_opts['ua_string'] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
extra_opts['ua_name'] = 'Internet Explorer'
extra_opts['ua_ver'] = '6.0'

ret = proxy.db.report_client(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
time.sleep(1)

#verify add
sys.stdout.write("Verifying Add Through clients: ")
ret = proxy.db.clients(token,extra_opts)
if ret['clients'] and len(ret['clients']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

#verify add
sys.stdout.write("Verifying Add Through get_client: ")
ret = proxy.db.get_client(token,extra_opts)
if ret['client'] and len(ret['client']) == 1:
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

sys.stdout.write("Deleting client: ")
ret = proxy.db.del_client(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
sys.stdout.write("Attempting to delete note: ")
extra_opts = {}	
extra_opts['host'] = '192.168.1.1'
extra_opts['port'] = 445
extra_opts['proto'] = "tcp"
extra_opts['ntype'] = "tnote"
ret = proxy.db.del_note(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
sys.stdout.write("Attempting to delete vuln: ")
del extra_opts['ntype']
extra_opts['name'] = "TestVuln1"
ret = proxy.db.del_vuln(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()
sys.stdout.write("Attempting to delete services...: ")
ret = proxy.db.del_service(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

sys.stdout.write("Attempting to delete hosts...: ")
extra_opts = {}	
extra_opts['addresses'] = ['192.168.1.1','192.168.1.2']
ret = proxy.db.del_host(token,extra_opts)
if ret['result'] == 'success':
	sys.stdout.write("OK\n")
else:
	sys.stdout.write("FAILED\n")
	sys.exit()

sys.stdout.write("Verifying what happens in vegas stays in vegas...: ")
extra_opts = {}	
extra_opts['addresses'] = ['192.168.1.1','192.168.1.2']
try:
	ret = proxy.db.fixOpts(extra_opts)
	sys.stdout.write("FAILED\n")
	sys.exit()
except:
	sys.stdout.write("OK\n")

