#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

# https://www.rfc-editor.org/rfc/rfc4178.txt

from asn1crypto.core import ObjectIdentifier, Sequence, SequenceOf, Enumerated, GeneralString, OctetString, BitString, Choice, Any
import enum
import os

TAG = 'explicit'

# class
UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2


class MechType(ObjectIdentifier):
	_map = {
		'1.3.6.1.4.1.311.2.2.10': 'NTLMSSP - Microsoft NTLM Security Support Provider',
		'1.2.840.48018.1.2.2'   : 'MS KRB5 - Microsoft Kerberos 5',
		'1.2.840.113554.1.2.2'  : 'KRB5 - Kerberos 5',
		'1.2.840.113554.1.2.2.3': 'KRB5 - Kerberos 5 - User to User',
		'1.3.6.1.4.1.311.2.2.30': 'NEGOEX - SPNEGO Extended Negotiation Security Mechanism',
}

class MechTypes(SequenceOf):
	_child_spec = MechType
	
class ContextFlags(BitString):
	_map = {
		0: 'delegFlag',
		1: 'mutualFlag',
		2: 'replayFlag',
		3: 'sequenceFlag',
		4: 'anonFlag',
		5: 'confFlag',
		6: 'integFlag',
}

class NegState(Enumerated):
	_map = {
		0: 'accept-completed',
		1: 'accept-incomplete',
		2: 'reject',
		3: 'request-mic',
}

class NegHints(Sequence):
	_fields = [
		('hintName', GeneralString, {'explicit': 0, 'optional': True}),
		('hintAddress', OctetString, {'explicit': 1, 'optional': True}),
]

# https://www.rfc-editor.org/rfc/rfc4178.txt 4.2.1
# EXTENDED IN: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/8e71cf53-e867-4b79-b5b5-38c92be3d472
class NegTokenInit2(Sequence):
	#explicit = (APPLICATION, 0)
	
	_fields = [
		('mechTypes', MechTypes, {'tag_type': TAG, 'tag': 0}),
		('reqFlags', ContextFlags, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('mechToken', OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('negHints', NegHints, {'tag_type': TAG, 'tag': 3, 'optional': True}),
		('mechListMIC', OctetString, {'tag_type': TAG, 'tag': 4, 'optional': True}),
]

# https://www.rfc-editor.org/rfc/rfc4178.txt 4.2.2

class NegTokenResp(Sequence):
	#explicit = (APPLICATION, 1)
	
	_fields = [
		('negState', NegState, {'tag_type': TAG, 'tag': 0, 'optional': True}),
		('supportedMech', MechType, {'tag_type': TAG, 'tag': 1, 'optional': True}),
		('responseToken', OctetString, {'tag_type': TAG, 'tag': 2, 'optional': True}),
		('mechListMIC', OctetString, {'tag_type': TAG, 'tag': 3, 'optional': True}),
]


class NegotiationToken(Choice):
	_alternatives = [
		('negTokenInit', NegTokenInit2, {'explicit': (CONTEXT, 0) } ),
		('negTokenResp', NegTokenResp, {'explicit': (CONTEXT, 1) } ),
]


class GSS_SPNEGO(Sequence):
	class_ = 2
	tag    = 0

	_fields = [
		('NegotiationToken', NegotiationToken),
]

### I have 0 idea where this is tandardized :(
class GSSType(ObjectIdentifier):
	_map = { 
		#'': 'SNMPv2-SMI::enterprises.311.2.2.30',
		'1.3.6.1.5.5.2': 'SPNEGO',
	}

class GSSAPI(Sequence):
	class_ = 1
	tag    = 0

	_fields = [
		('type', GSSType, {'optional': False}),
		('value', Any, {'optional': False}),
	]

	_oid_pair = ('type', 'value')
	_oid_specs = {
		'SPNEGO': NegotiationToken,
	}
