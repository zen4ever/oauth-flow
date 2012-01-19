#!/usr/bin/env python

from distutils.core import setup
import os

setup(name='django-oauth-flow',
      version='1.0a',
      description='Authenticate and make calls to OAuth 1.0, OAuth 2.0 services',
      author='Andrii Kurinnyi',
      author_email='andrew@zen4ever.com',
      url='http://github.com/zen4ever/django-linked-accounts',
      packages=['oauth_flow',],
      keywords=['django', 'oauth', 'twitter', 'facebook'],
      classifiers=[
          'Development Status :: 1 - Planning',
          'Programming Language :: Python',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Operating System :: OS Independent',
          'Framework :: Django',
      ],
      long_description=open(
          os.path.join(os.path.dirname(__file__), 'README.rst'),
      ).read().strip(),
)
