import enum

class NegotiateDialects(enum.Enum):
	WILDCARD = 0x02FF
	SMB202 = 0x0202 #SMB 2.0.2 dialect revision number.
	SMB210 = 0x0210 #SMB 2.1 dialect revision number.<10>
	SMB222 = 0x0222
	SMB224 = 0x0224
	SMB300 = 0x0300 #SMB 3.0 dialect revision number. <11>
	SMB302 = 0x0302 #SMB 3.0.2 dialect revision number.<12>
	SMB310 = 0x0310 #SMB 3.1.1 dialect revision number.<13>
	SMB311 = 0x0311 #SMB 3.1.1 dialect revision number.<13>

SMB2_NEGOTIATE_DIALTECTS_2 = {
	NegotiateDialects.SMB202 : 1,
	NegotiateDialects.SMB210 : 1,
	#NegotiateDialects.SMB222 : 1,
	#NegotiateDialects.SMB224 : 1
}
SMB2_NEGOTIATE_DIALTECTS_3 = {
	NegotiateDialects.SMB300 : 1,
	NegotiateDialects.SMB302 : 1,
	#NegotiateDialects.SMB310 : 1,
	NegotiateDialects.SMB311 : 1
}
SMB2_NEGOTIATE_DIALTECTS = {
	NegotiateDialects.SMB202 : 1,
	NegotiateDialects.SMB210 : 1,
	NegotiateDialects.SMB300 : 1,
	NegotiateDialects.SMB302 : 1,
	NegotiateDialects.SMB311 : 1
}

SMB_NEGOTIATE_PROTOCOL_TEST = {
	NegotiateDialects.WILDCARD : 1,
	NegotiateDialects.SMB202 : 1,
	NegotiateDialects.SMB210 : 1,
	NegotiateDialects.SMB300 : 1,
	NegotiateDialects.SMB302 : 1,
	NegotiateDialects.SMB311 : 1
}