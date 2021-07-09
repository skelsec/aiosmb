
##this file is present to force pure ciphers to be used
## reason: pyinstaller cant do dynamic imports
## usage: overwrite the "symmetric.py" file with tihs one

from aiosmb.crypto.AES import pyCryptodomeAES
from aiosmb.crypto.DES import pyCryptodomeDES
from aiosmb.crypto.RC4 import pyCryptodomeRC4
from aiosmb.crypto.AESCCM_dome import aesCCMEncrypt as ae
from aiosmb.crypto.AESCCM_dome import aesCCMDecrypt as ad

DES = pyCryptodomeDES
AES = pyCryptodomeAES
RC4 = pyCryptodomeRC4

aesCCMEncrypt = ae
aesCCMDecrypt = ad