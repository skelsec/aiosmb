

#
# Currently supported auth types:
#      NTLM auth using SMBNTLM implementation
#      Kerberos auth using SMBSPNEGO implementation (GSSAPI)
#
# Not supported currently:
#      NTLM via SPNEGO (GSSAPI)
#      Direct kerberos auth (not sure if this is even in the protocol)
#      NETLOGON
#
# TODO: netlogon implementation (needs to be implemented in connection.py as well!)
# TODO: GSS over NTLM (but I'm not sure if the protocol allows that)

class DCERPCAuth:
    def __init__(self):
        self.ntlm = None
        self.kerberos = None
        self.gssapi = None
        self.netlogon = None

    @staticmethod
    def from_smb_gssapi(gssapi):
        auth = DCERPCAuth()
        auth.gssapi = gssapi.get_copy()
        if 'MS KRB5 - Microsoft Kerberos 5' in gssapi.list_original_conexts():
            auth.kerberos = gssapi.get_original_context('MS KRB5 - Microsoft Kerberos 5')
        if 'NTLMSSP - Microsoft NTLM Security Support Provider' in gssapi.list_original_conexts():
            auth.ntlm = gssapi.get_original_context('NTLMSSP - Microsoft NTLM Security Support Provider')

        return auth

