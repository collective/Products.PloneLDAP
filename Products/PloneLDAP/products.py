from zope.interface import implementer
from Products.CMFQuickInstallerTool.interfaces import INonInstallable

@implementer(INonInstallable)
class HiddenLDAPProducts(object):

    def getNonInstallableProducts(self):
        return [ "LDAPUserFolder" ]
