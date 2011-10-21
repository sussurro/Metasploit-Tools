import xmlrpclib
class MSFTransport(xmlrpclib.Transport):
    """Handles an transaction to the MetasploitXML-RPC server."""

    # client identifier (may be overridden)
    def __init__(self, use_datetime=0):
        self._use_datetime = use_datetime

    ##
    # Send a complete request, and parse the response.
    #
    # @param host Target host.
    # @param handler Target PRC handler.
    # @param request_body XML-RPC request body.
    # @param verbose Debugging flag.
    # @return Parsed response.

    def request(self, host, handler, request_body, verbose=0):
        # issue XML-RPC request

        c = self.make_connection(host)
        if verbose:
            h.set_debuglevel(1)

        self.send_content(c, request_body)

        self.verbose = verbose

        return self._parse_response(None, c)

    ##
    # Connect to server.
    #
    # @param host Target host.
    # @return A connection handle.

    def make_connection(self, host):
    	import socket
	addr = host.split(":")
	inetaddr = (addr[0],int(addr[1]))

	c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	c.connect(inetaddr)

        return c

    ##
    # Send request body.
    #
    # @param connection Connection handle.
    # @param request_body XML-RPC request body.

    def send_content(self, connection, request_body):
        if request_body:
            connection.send(request_body + "\0")

    def _parse_response(self, file, sock):
        # read response from input file/socket, and parse it

        p, u = self.getparser()

        while 1:
            if sock:
                response = sock.recv(1024)
            else:
                response = file.read(1024)
            if not response:
                break
	    if response.endswith("\0")	:
		response = response.rstrip("\0\n")
            	p.feed(response.encode("utf-8"))
	    	break;
	    else:
            	p.feed(response.encode("utf-8"))

	if file:
        	file.close()
        p.close()

        return u.close()


