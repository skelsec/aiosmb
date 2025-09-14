from setuptools import setup, find_packages
import re

VERSIONFILE="aiosmb/_version.py"
verstrline = open(VERSIONFILE, "rt").read()
VSRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
mo = re.search(VSRE, verstrline, re.M)
if mo:
    verstr = mo.group(1)
else:
    raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE,))

setup(
	# Application name:
	name="aiosmb",

	# Version number (initial):
	version=verstr,

	# Application author details:
	author="Tamas Jos",
	author_email="info@skelsecprojects.com",

	# Packages
	packages=find_packages(exclude=["tests*"]),

	# Include additional files into the package
	include_package_data=True,
	license="Modified Apache Software License 1.1",

	# Details
	url="https://github.com/skelsec/aiosmb",

	zip_safe = False,
	#
	# license="LICENSE.txt",
	description="Asynchronous SMB protocol implementation",

	# long_description=open("README.txt").read(),
	python_requires='>=3.7',
	install_requires=[
		'unicrypto>=0.0.10',
		'asyauth>=0.0.22',
		'asysocks>=0.2.17',
		'prompt-toolkit>=3.0.2',
		'winacl>=0.1.9',
		'six',
		'tqdm',
		'colorama',
		'asn1crypto',
		'wcwidth',
        'cryptography',
	],
	
	classifiers=[
		"Programming Language :: Python :: 3.7",
		"Operating System :: OS Independent",
	],
	entry_points={
		'console_scripts': [
			'asmbclient = aiosmb.examples.smbclient:main',
			'asmbshareenum = aiosmb.examples.smbshareenum:main',
			'asmbgetfile = aiosmb.examples.smbgetfile:main',
			'asmbcertreq = aiosmb.examples.smbcertreq:main',
			'asmbscanner = aiosmb.examples.scanners.__main__:main'
		],

	}
)