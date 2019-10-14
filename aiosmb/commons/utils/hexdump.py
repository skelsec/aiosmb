
# https://gist.github.com/ImmortalPC/c340564823f283fe530b
def hexdump(src, length=16, sep='.'):
	"""
	Pretty printing binary data blobs
	:param src: Binary blob
	:type src: bytearray
	:param length: Size of data in each row
	:type length: int
	:param sep: Character to print when data byte is non-printable ASCII
	:type sep: str(char)
	:return: str
	"""
	result = []

	for i in range(0, len(src), length):
		subSrc = src[i:i+length]
		hexa = ''
		isMiddle = False
		for h in range(0,len(subSrc)):
			if h == length/2:
				hexa += ' '
			h = subSrc[h]
			if not isinstance(h, int):
				h = ord(h)
			h = hex(h).replace('0x', '')
			if len(h) == 1:
				h = '0'+h
			hexa += h+' '
		hexa = hexa.strip(' ')
		text = ''
		for c in subSrc:
			if not isinstance(c, int):
				c = ord(c)
			if 0x20 <= c < 0x7F:
				text += chr(c)
			else:
				text += sep
		result.append(('%08X:  %-'+str(length*(2+1)+1)+'s  |%s|') % (i, hexa, text))

	return '\n'.join(result)