from aiosmb.dcerpc.v5.transport.common import *
from aiosmb.dcerpc.v5.transport.tcptransport import TCPTransport
from aiosmb.dcerpc.v5.transport.smbtransport import SMBTransport

def DCERPCTransportFactory(stringbinding, connection):
	sb = DCERPCStringBinding(stringbinding, connection)

	na = sb.get_network_address()
	ps = sb.get_protocol_sequence()
	if 'ncadg_ip_udp' == ps:
		raise Exception('Not Implemented!')
		#port = sb.get_endpoint()
		#if port:
		#	return UDPTransport(na, int(port))
		#else:
		#	return UDPTransport(na)
	elif 'ncacn_ip_tcp' == ps:
		port = sb.get_endpoint()
		if port:
			return TCPTransport(connection, na, int(port))
		else:
			return TCPTransport(connection, na)
	elif 'ncacn_http' == ps:
		raise Exception('Not Implemented!')
		#port = sb.get_endpoint()
		#if port:
		#	return HTTPTransport(na, int(port))
		#else:
		#	return HTTPTransport(na)
	elif 'ncacn_np' == ps:
		named_pipe = sb.get_endpoint()
		if named_pipe:
			named_pipe = named_pipe[len(r'\pipe'):]
			return SMBTransport(connection, na, filename = named_pipe)
		else:
			return SMBTransport(connection, na)
	elif 'ncalocal' == ps:
		raise Exception('Not Implemented!')
		#named_pipe = sb.get_endpoint()
		#return LOCALTransport(filename = named_pipe)
	else:
		raise DCERPCException("Unknown protocol sequence.")