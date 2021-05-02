
import hashlib


def truncate_key(value, keysize):
			output = b''
			currentNum = 0
			while len(output) < keysize:
				currentDigest = hashlib.sha1(bytes([currentNum]) + value).digest()
				if (len(output) + len(currentDigest)) > keysize:
					output += currentDigest[:keysize - len(output)]
					break
				output += currentDigest
				currentNum += 1
			
			return output


data = bytes.fromhex('997cd67f2c1a4ae59d35ebabd44506304db082914e2462c011c0c1f979207d7bc6ec1821a485b678dd73a7b9b2740cec36fd55d397d5f641426c6f9947296656490ae15641decdf6f3f89dcfd04b421a20a3acc79ce09cee1abddd3a4df56d9dad234d3cc33be3b2bfae2f26d5888819d6ef3600b5854af3aab6514df375eefe6B328FA66EEBDFD3D69ED34E5007776AB30832A2ED1DCB1699781BFE0BEDF87A4357b57066af3142dc8dc8519f5224fb1c282d8b8808b9a4308980203421e77e')

output = truncate_key(data, 32)
print(output.hex())