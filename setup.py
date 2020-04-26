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
	author_email="info@skelsec.com",

	# Packages
	packages=find_packages(),

	# Include additional files into the package
	include_package_data=True,


	# Details
	url="https://github.com/skelsec/aiosmb",

	zip_safe = True,
	#
	# license="LICENSE.txt",
	description="Asynchronous SMB protocol implementation",

	# long_description=open("README.txt").read(),
	python_requires='>=3.7',
	install_requires=[
		'minikerberos>=0.2.1',
		'winsspi>=0.0.9',
		'six',
		'aiocmd>=0.1.2',
		'asysocks>=0.0.3',
		'tqdm',
		'prompt-toolkit<3.0.0'
	],
	
	classifiers=(
		"Programming Language :: Python :: 3.7",
		"License :: OSI Approved :: MIT License",
		"Operating System :: OS Independent",
	),
	entry_points={
		'console_scripts': [
			'aiosmbclient = aiosmb.examples.smbclient:main',
		],

	}
)