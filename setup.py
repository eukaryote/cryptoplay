# No future imports here so that unsupported Python versions will get a useful
# error message with version requirements rather than an ImportError.

from setuptools import setup
from setuptools.command.test import test as testcommand

from os.path import abspath, dirname, join
import sys

import cryptoplay

if sys.version_info < (2, 7):
    sys.stdout.write("requires Python 2.7 or greater\n")
    sys.exit(1)

here_dir = abspath(dirname(__file__))


def read(*filenames):
    buf = []
    for filename in filenames:
        filepath = join(here_dir, filename)
        with open(filepath, 'r') as f:
            buf.append(f.read())
    return '\n\n'.join(buf)


class PyTest(testcommand):

    def finalize_options(self):
        testcommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest
        errcode = pytest.main(self.test_args)
        sys.exit(errcode)


setup(
    name='cryptoplay',
    version=cryptoplay.__version__,
    url='http://github.com/eukaryote/cryptoplay/',
    license='Apache Software License',
    author='Calvin Smith',
    author_email='sapientdust+cryptoplay@gmail.com',
    tests_require=['pytest', 'mock'],
    install_requires=[],
    cmdclass={'test': PyTest},
    description=(
        'Crypto utilities for interactive crypto experimentation'
    ),
    #long_description=read('README.rst', 'CHANGES.rst'),
    packages=['cryptoplay'],
    include_package_data=True,
    platforms='any',
    test_suite='tests',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha'
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Natural Language :: English',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography'
    ],
    extras_require={
        'testing': ['pytest', 'pytest-xdist', 'mock'],
        'develop': ['wheel'],
    }
)
