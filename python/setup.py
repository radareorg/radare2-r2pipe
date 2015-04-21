from distutils.core import setup
import r2pipe

with open('README.rst') as readme_file:
    readme = readme_file.read()

setup(
    name='r2pipe',
    version=r2pipe.version(),
    license='MIT',
    description='Pipe interface for radare2',
    long_description=readme,
    author='pancake',
    author_email='pancake@nopcode.org',
    url='http://rada.re',
    package_dir={'r2pipe': 'r2pipe'},
    packages=['r2pipe']
)
