from setuptools import setup, find_packages

version = '2.0.0a1'

setup(name='Products.PloneLDAP',
      version=version,
      description="LDAP/Active Directory support for Plone",
      long_description=(open('README.txt').read() +
                        open('CHANGES.rst').read()),
      classifiers=[
          "Framework :: Plone",
          "Framework :: Zope2",
          "Programming Language :: Python",
          "Topic :: Software Development :: Libraries :: Python Modules",
          "Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP",
          "License :: OSI Approved :: Zope Public License",
          ],
      keywords='Zope CMF Plone LDAP authentication',
      author='Wichert Akkerman - Simpon',
      author_email='wichert@simplon.biz',
      url='https://github.com/collective/Products.PloneLDAP',
      license='Zope Public License 2.1',
      packages=find_packages(exclude=['ez_setup']),
      namespace_packages=['Products'],
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'Products.PlonePAS',
          'Products.LDAPMultiPlugins',
          'Products.LDAPUserFolder',
          ],
      )
