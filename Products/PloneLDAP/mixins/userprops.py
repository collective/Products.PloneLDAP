from Globals import InitializeClass
from AccessControl import ClassSecurityInfo
from Products.PloneLDAP.property import LDAPPropertySheet
from Products.PlonePAS.plugins.group import PloneGroup

class UserPropertiesMixin:
    """Implement Products.PluggableAuthService.interfaces.plugins.IPropertiesPlugin
    and Products.PlonePAS.interfaces.plugtins.IMutablePropertiesPlugin
    """
    security = ClassSecurityInfo()

    security.declarePrivate('getPropertiesForUser')
    def getPropertiesForUser(self, user, request=None):
        """ Fullfill PropertiesPlugin requirements """
        if isinstance(user, PloneGroup):
           return None
        try:
            return LDAPPropertySheet(self.id, user)
        except KeyError:
            return None


    security.declarePrivate('setPropertiesForUser')
    def setPropertiesForUser(self, user, propertysheet):
        """Set the properties of a user or group based on the contents of a
        property sheet. Needed for IMutablePropertiesPlugin.

       This is probably unused code: PlonePAS uses IMutablePropertySheet
       instead.
        """
        acl = self._getLDAPUserFolder()

        if acl is None:
            return

        ldap_user = acl.getUserById(user.getId())

        if ldap_user is None:
            return

        schemaproperties = dict([(x['public_name'], x['ldap_name']) \
                for x in acl.getSchemaConfig().values() if x['public_name']])
        multivaluedprops = [x['public_name'] for x in acl.getSchemaConfig().values() \
               if x['multivalued']]

        changes={}
        for (key,value) in propertysheet.propertyItems():
            if key in schemaproperties and key!=acl._rdnattr:
                if key in multivaluedprops:
                    changes[key] = [x.strip() for x in value.split(';')]
                else:
                    changes[key] = [value.strip()]
                    changes[key] = [value.strip()]

        acl._delegate.modify(ldap_user.dn, changes)

    def deleteUser(self, id):
        """ Delete the users properties. """
        # Since properties are an inherit part of the user herself and at
        # at least for Plone the user is deleted before the memberdata
        # we just do nothing here.
        return


InitializeClass(UserPropertiesMixin)

