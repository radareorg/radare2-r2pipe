from distutils.core import setup

setup (
	name='r2pipe',
	version='0.3',
	license='MIT',
	description='Pipe interface for radare2',
	author='pancake',
	author_email='pancake@nopcode.org',
	url='http://rada.re',
	package_dir={'r2pipe': 'r2pipe'},
	packages=['r2pipe']
)
