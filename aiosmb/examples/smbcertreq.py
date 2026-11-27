
# This example is based on the awesome code of @zer1t0 's certi project
# https://github.com/zer1t0/certi
# 

import asyncio
import traceback
import logging
import os

from aiosmb import logger
from aiosmb._version import __banner__
from aiosmb.commons.connection.factory import SMBConnectionFactory
from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC
from aiosmb.dcerpc.v5.connection import DCERPC5Connection
from aiosmb.dcerpc.v5.common.connection.authentication import DCERPCAuth
from aiosmb.dcerpc.v5.interfaces.endpointmgr import EPM
from aiosmb.examples._cli import (
	CONNECTION_EPILOG,
	add_url_help,
	add_verbosity,
	make_parser,
)

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs7, pkcs12, BestAvailableEncryption, load_pem_private_key
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from asn1crypto import core

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


async def amain(url, service, template, altname, onbehalf, cn = None, pfx_file = None, pfx_password = None, enroll_cert = None, enroll_password = None):
	try:
		if pfx_file is None:
			pfx_file = 'cert_%s.pfx' % os.urandom(4).hex()
		if pfx_password is None:
			pfx_password = 'admin'
		
		print('[+] Parsing connection parameters...')
		su = SMBConnectionFactory.from_url(url)
		ip = su.get_target().get_hostname_or_ip()

		if cn is None:
			cn = '%s@%s' % (su.credential.username, su.credential.domain)
		
		print('[*] Using CN: %s' % cn)
		
		print('[+] Generating RSA privat key...')
		key = rsa.generate_private_key(0x10001, 2048)

		print('[+] Building certificate request...')
		attributes = {
			"CertificateTemplate": template,
		}
		csr = x509.CertificateSigningRequestBuilder()
		csr = csr.subject_name(
				x509.Name(
					[
						x509.NameAttribute(NameOID.COMMON_NAME, cn),
					]
				)
			)

		if altname:
			altname = core.UTF8String(altname).dump()
			csr = csr.add_extension(
				x509.SubjectAlternativeName(
					[
						x509.OtherName(PRINCIPAL_NAME, altname),
					]
				),
				critical=False,
			)

		csr = csr.sign(key, hashes.SHA256())
		
		if onbehalf is not None:
			agent_key = None
			agent_cert = None
			with open(enroll_cert, 'rb') as f:
				agent_key, agent_cert, _ = pkcs12.load_key_and_certificates(f.read(), enroll_password)
				
			pkcs7builder = pkcs7.PKCS7SignatureBuilder().set_data(csr).add_signer(agent_key, agent_cert, hashes.SHA1())
			csr = pkcs7builder.sign(Encoding.DER, options=[pkcs7.PKCS7Options.Binary])
		else:
			csr = csr.public_bytes(Encoding.DER)
		
		print('[+] Connecting to EPM...')
		target, err = await EPM.create_target(ip, ICPRRPC().service_uuid, dc_ip = su.get_target().dc_ip, domain = su.get_target().domain)
		if err is not None:
			raise err
		
		print('[+] Connecting to ICRPR service...')
		auth = DCERPCAuth.from_smb_gssapi(su.get_credential())
		connection = DCERPC5Connection(auth, target)
		rpc, err = await ICPRRPC.from_rpcconnection(connection, perform_dummy=True)
		if err is not None:
			raise err
		logger.debug('DCE Connected!')
		
		print('[+] Requesting certificate from the service...')
		res, err = await rpc.request_certificate(service, csr, attributes)
		if err is not None:
			print('[-] Request failed!')
			raise err
		
		
		if res['encodedcert'] in [None, b'']:
			raise Exception('No certificate was returned from server!. Full message: %s' % res)
		
		print('[+] Got certificate!')
		cert = x509.load_der_x509_certificate(res['encodedcert'])
		print("[*]   Cert subject: {}".format(cert.subject.rfc4514_string()))
		print("[*]   Cert issuer: {}".format(cert.issuer.rfc4514_string()))
		print("[*]   Cert Serial: {:X}".format(cert.serial_number))
		
		try:
			ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
			for oid in ext.value:
				print("[*]   Cert Extended Key Usage: {}".format(oid.dotted_string))
		except:
			print('[-]   Could not verify extended key usage')

		try:
			ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
			for name in ext.value.get_values_for_type(x509.OtherName):
				if name.type_id == x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"):
					print('[*]   Certificate ALT NAME: %s' % core.UTF8String.load(name.value).native)
					break
			else:
				print('[-]   Certificate doesnt have ALT NAME')
		except:
			print('[-]   Certificate doesnt have ALT NAME')
		
		print('[+] Writing certificate to disk (file:"%s" pass: "%s")...' % (pfx_file, pfx_password))
		
		# Still waiting for the day oscrypto will have a pfx serializer :(
		# Until that we'd need to use cryptography
		with open(pfx_file, 'wb') as f:
			data = pkcs12.serialize_key_and_certificates(
				name=b"",
				key=key,
				cert=cert,
				cas=None,
				encryption_algorithm=BestAvailableEncryption(pfx_password.encode())
			)
			f.write(data)

		print('[+] Finished!')
		return True, None
	except Exception as e:
		traceback.print_exc()
		return False, e


def build_parser(prog=None):
	parser = make_parser(
		'Request a certificate through the Microsoft ICPR RPC service',
		prog=prog,
		epilog=CONNECTION_EPILOG,
	)
	add_url_help(parser)

	output = parser.add_argument_group('certificate output')
	output.add_argument(
		'--pfx-file',
		metavar='PATH',
		help='output PFX path; defaults to cert_<random>.pfx',
	)
	output.add_argument(
		'--pfx-pass',
		default='admin',
		metavar='PASSWORD',
		help='password used to encrypt the output PFX',
	)

	subject = parser.add_argument_group('certificate subject')
	subject.add_argument(
		'--alt-name',
		metavar='PRINCIPAL',
		help='UPN placed in the subject alternative name, usually user@domain',
	)
	subject.add_argument(
		'--cn',
		metavar='NAME',
		help='common name; defaults to the authenticated user principal',
	)

	agentenroll = parser.add_argument_group('Agent enrollment parameters')
	agentenroll.add_argument(
		'--on-behalf',
		metavar='PRINCIPAL',
		help='request the certificate on behalf of this principal',
	)
	agentenroll.add_argument(
		'--enroll-cert',
		metavar='PATH',
		help='enrollment-agent PFX used to sign the request',
	)
	agentenroll.add_argument(
		'--enroll-pass',
		metavar='PASSWORD',
		help='password for the enrollment-agent PFX',
	)

	diagnostics = parser.add_argument_group('diagnostics')
	add_verbosity(diagnostics)

	parser.add_argument(
		'smb_url',
		metavar='URL',
		help='SMB connection URL for the certificate server; use --help-url',
	)
	parser.add_argument(
		'service',
		metavar='CA',
		help='certificate authority name passed to the ICPR service',
	)
	parser.add_argument(
		'template',
		metavar='TEMPLATE',
		help='certificate template name',
	)
	return parser


def main(argv=None):
	parser = build_parser()
	
	args = parser.parse_args(argv)
	print(__banner__)

	if args.verbose >=1:
		logger.setLevel(logging.DEBUG)

	asyncio.run(
		amain(
			args.smb_url,
			args.service,
			args.template,
			args.alt_name,
			args.on_behalf,
			args.cn,
			args.pfx_file,
			args.pfx_pass,
			args.enroll_cert,
			args.enroll_pass
		)
	)

if __name__ == '__main__':
	main()