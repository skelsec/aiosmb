
##this file is present to force pure ciphers to be used
## reason: pyinstaller cant do dynamic imports
## usage: overwrite the "symmetric.py" file with tihs one

from aiosmb.crypto.AES import pureAES
from aiosmb.crypto.DES import pureDES
from aiosmb.crypto.RC4 import pureRC4
from aiosmb.crypto.pure.AES.AESCCM import aesCCMEncrypt as ae
from aiosmb.crypto.pure.AES.AESCCM import aesCCMDecrypt as ad

DES = pureDES
AES = pureAES
RC4 = pureRC4

aesCCMEncrypt = ae
aesCCMDecrypt = ad
