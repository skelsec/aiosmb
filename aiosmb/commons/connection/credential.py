from enum import Enum

class SMBCredentialTypes(str, Enum):
    NTLM_PASSWORD = "ntlm-password"
    NTLM_NT = "ntlm-nt"
    SSPI_NTLM = "sspi-ntlm"
    KERBEROS_PASSWORD = "kerberos-password"
    KERBEROS_NT = "kerberos-nt"
    KERBEROS_PFX = "kerberos-pfx"
    KERBEROS_PEM = "kerberos-pem"
    SSPI_KERBEROS = "sspi-kerberos"
    NEGOEX_PFX = "negoex-pfx"
    NEGOEX_CERTSTORE = "negoex-certstore"
