import logging
from zope.interface import implementedBy
from AccessControl import ClassSecurityInfo
from Globals import InitializeClass
from Products.LDAPMultiPlugins.LDAPMultiPlugin import LDAPMultiPlugin
from Products.PluggableAuthService.interfaces.plugins import (
    IUserEnumerationPlugin, IGroupsPlugin, IGroupEnumerationPlugin,
    IRoleEnumerationPlugin, IUserAdderPlugin,
    IAuthenticationPlugin, IRolesPlugin,
    ICredentialsResetPlugin, IPropertiesPlugin)

from Products.PluggableAuthService.utils import classImplements
from Products.PlonePAS.interfaces.capabilities import IDeleteCapability
from Products.PlonePAS.interfaces.capabilities import IPasswordSetCapability
from Products.PlonePAS.interfaces.plugins import IUserManagement
from Products.PlonePAS.interfaces.capabilities import IGroupCapability
from Products.PlonePAS.interfaces.group import IGroupIntrospection
from Products.PlonePAS.interfaces.group import IGroupManagement
from Products.PlonePAS.interfaces.plugins import IMutablePropertiesPlugin

from Products.PloneLDAP.plugins.base import PloneLDAPPluginBaseMixin
from Products.PloneLDAP.mixins import UserAdderMixin
from Products.PloneLDAP.mixins import UserManagementMixin
from Products.PloneLDAP.mixins import UserPropertiesMixin
from Products.PloneLDAP.mixins import GroupCapabilityMixin
from Products.PloneLDAP.mixins import GroupIntrospectionMixin
from Products.PloneLDAP.mixins import GroupManagementMixin

logger = logging.getLogger("PloneLDAP")


class PloneLDAPMultiPlugin(PloneLDAPPluginBaseMixin,
        UserAdderMixin, UserManagementMixin, UserPropertiesMixin,
        GroupCapabilityMixin, GroupIntrospectionMixin, GroupManagementMixin,
        LDAPMultiPlugin):
    """Plone LDAP plugin.
    """
    security = ClassSecurityInfo()
    meta_type = "Plone LDAP plugin"

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
        results= LDAPMultiPlugin.enumerateGroups(
            self, id, exact_match, sort_by, max_results, **kw)
        self.prefetched_groups.update((x['id'], x) for x in results)
        return results


classImplements(
    PloneLDAPMultiPlugin,
    IAuthenticationPlugin,
    ICredentialsResetPlugin,
    IDeleteCapability,
    IGroupCapability,
    IGroupEnumerationPlugin,
    IGroupIntrospection,
    IGroupManagement,
    IGroupsPlugin,
    IMutablePropertiesPlugin,
    IPasswordSetCapability,
    IPropertiesPlugin,
    IRoleEnumerationPlugin,
    IRolesPlugin,
    IUserAdderPlugin,
    IUserEnumerationPlugin,
    IUserManagement,
    *implementedBy(LDAPMultiPlugin)
    )

InitializeClass(PloneLDAPMultiPlugin)
