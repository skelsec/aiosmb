# https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
def sizeof_fmt(num, suffix='B'):
	if num is None:
		return ''
	for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
		if abs(num) < 1024.0:
			return "%3.1f%s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f%s%s" % (num, 'Yi', suffix)


def size_to_bytes(size_str:str):
	if size_str == '' or size_str is None:
		return None
	
	size_str = size_str.upper()
	allowed_sizes = 'TGMK'
	
	if size_str[-1].isdigit() is False:
		for c in allowed_sizes:
			if size_str.endswith(c) is True:
				break
		else:
			raise ValueError(f"Invalid size format: {size_str}")
	
	size_str = size_str.strip().upper()
	
	if not size_str:
		raise ValueError("Empty string provided")
	
	# Get the numeric part and the unit
	try:
		if 'T' in size_str:
			return int(float(size_str.replace('G', '')) * 1024 * 1024 * 1024 * 1024)
		elif 'G' in size_str:
			return int(float(size_str.replace('G', '')) * 1024 * 1024 * 1024)
		elif 'M' in size_str:
			return int(float(size_str.replace('M', '')) * 1024 * 1024)
		elif 'K' in size_str:
			return int(float(size_str.replace('K', '')) * 1024)
		else:  # Assume bytes if no unit is provided
			return int(size_str)
	except ValueError:
		raise ValueError(f"Invalid size format: {size_str}")