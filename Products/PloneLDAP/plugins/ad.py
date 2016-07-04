import logging
from zope.interface import implementedBy
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from Products.LDAPMultiPlugins.ActiveDirectoryMultiPlugin import (
    ActiveDirectoryMultiPlugin)
from Products.PluggableAuthService.interfaces.plugins import (
    IUserEnumerationPlugin, IGroupsPlugin, IGroupEnumerationPlugin,
    IRoleEnumerationPlugin, IAuthenticationPlugin, IRolesPlugin,
    ICredentialsResetPlugin, IPropertiesPlugin)

from Products.PluggableAuthService.utils import classImplements
from Products.PlonePAS.interfaces.group import IGroupIntrospection
from Products.PlonePAS.interfaces.plugins import IMutablePropertiesPlugin

from Products.PloneLDAP.plugins.base import PloneLDAPPluginBaseMixin
from Products.PloneLDAP.mixins import UserPropertiesMixin
from Products.PloneLDAP.mixins import GroupIntrospectionMixin

logger = logging.getLogger("PloneLDAP")


class PloneActiveDirectoryMultiPlugin(PloneLDAPPluginBaseMixin,
        UserPropertiesMixin, GroupIntrospectionMixin,
        ActiveDirectoryMultiPlugin):
    """Plone Active Directory plugin.
    """
    security = ClassSecurityInfo()
    meta_type = "Plone Active Directory plugin"

    security.declarePrivate('enumerateGroups')
    def enumerateGroups(self, id=None, exact_match=False, sort_by=None,
                        max_results=None, **kw):
        """Group enumeration.

        This method adds a workaround to enforce LDAPUserFolder to return a
        list of all groups. This is desirable for LDAP environments where only
        a few groups are present. In Plone we know this in advance thanks to
        the 'many groups' setting.
        """
        if exact_match and id:
            group = self.prefetched_groups.get(id)
            if group is False:
                return ()
            elif group is not None:
                return [group]
        if not id and not kw:
            kw["cn"]=""
        result = ActiveDirectoryMultiPlugin.enumerateGroups(
            self, id, exact_match, sort_by, max_results, **kw)
        self.prefetched_groups.update((x['id'], x) for x in results)
        return results


classImplements(
    PloneActiveDirectoryMultiPlugin,
    IAuthenticationPlugin,
    ICredentialsResetPlugin,
    IGroupEnumerationPlugin,
    IGroupIntrospection,
    IGroupsPlugin,
    IMutablePropertiesPlugin,
    IPropertiesPlugin,
    IRoleEnumerationPlugin,
    IRolesPlugin,
    IUserEnumerationPlugin,
    *implementedBy(ActiveDirectoryMultiPlugin)
    )

InitializeClass(PloneActiveDirectoryMultiPlugin)
