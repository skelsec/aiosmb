from aiosmb.commons.interfaces.directory import SMBDirectory
from aiosmb.connection import SMBConnection
from aiosmb.commons.interfaces.file import SMBFile

from xml.dom import minidom

async def dummy_print_cb(data:str):
	return

def parse_cpasswd(filename, data):
	results = []
	root = minidom.parseString(data)
	xmltype = root.childNodes[0].tagName
	read_or_empty = lambda element, attribute: (element.getAttribute(attribute) if element.getAttribute(attribute) is not None else "")
	for topnode in root.childNodes:
		for task in [c for c in topnode.childNodes if isinstance(c, minidom.Element)]:
			for property in task.getElementsByTagName("Properties"):
				username = read_or_empty(property, "userName")
				cpassword = read_or_empty(property, "cpassword")
				results.append({
					"username": username,
					"cpassword": cpassword,
					"filename": filename,
					"xmltype": xmltype
				})
	return results


async def find_cpasswd(connection:SMBConnection, depth = 5, print_cb = dummy_print_cb):
	try:
		uncpath = '\\\\%s\\%s' % (connection.target.get_hostname_or_ip(), 'SYSVOL')
		sysvol = SMBDirectory.from_uncpath(uncpath)
		async for path, otype, err in sysvol.list_r(connection, depth = depth):
			if err is not None:
				continue
			if otype == 'file':
				if path.fullpath.endswith('.xml') is True:
					await print_cb(path.unc_path)
					file = SMBFile.from_uncpath(path.unc_path)
					_, err = await file.open(connection)
					if err is not None:
						continue
					data, err = await file.read()
					if err is not None:
						continue
					await file.close()
					data = data.decode('utf-8', errors='ignore')
					if data.lower().find('cpassword') is False:
						continue
						
					try:
						results = parse_cpasswd(path.unc_path, data)
					except Exception as e:
						await print_cb('[-] Error parsing xml file: %s' % e)
						continue
					for result in results:
						if result.get('cpassword', '') != "":
							continue
						yield result['filename'], result['username'], result['cpassword'], result['xmltype'], None


	except Exception as e:
		yield None, None, None, None, e