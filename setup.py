from setuptools import setup, find_packages

setup(
	# Application name:
	name="aiosmb",

	# Version number (initial):
	version="0.1.4",

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
		'minikerberos>=0.0.11',
		'winsspi>=0.0.2',
		'six',
		'aiocmd',
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