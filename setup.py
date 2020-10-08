from setuptools import setup

setup(name='pam-websso',
      version='0.1',
      description='WebSSO PAM Module',
      url='https://github.com/mrvanes/pam-websso',
      author='Martin van Es',
      author_email='pam-websso@mrvanes.com',
      license='GPL',
      install_requires=[
          'Twisted',
          'python3-saml',
          'pyOpenSSL',
          'service_identity',
          'requests'
          ],
      zip_safe=False
      )
