#!/usr/bin/env python

from setuptools import setup, find_packages
import os

setup(name='oauth-flow',
      version='1.0.3',
      description='Authenticate and make calls to OAuth 1.0, OAuth 2.0 services',
      author='Andrii Kurinnyi',
      author_email='andrew@zen4ever.com',
      url='https://github.com/zen4ever/oauth-flow',
      packages=find_packages(),
      keywords=['oauth', 'twitter', 'facebook'],
      classifiers=[
          'Development Status :: 1 - Planning',
          'Programming Language :: Python',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
      ],
      install_requires=['httplib2', 'oauth2'],
      long_description=open(
          os.path.join(os.path.dirname(__file__), 'README.rst'),
      ).read().strip(),
)
