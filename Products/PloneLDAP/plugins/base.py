import logging
try:
    from hashlib import sha1 as sha_new
except ImportError:
    from sha import new as sha_new
from Globals import InitializeClass
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from Products.PluggableAuthService.utils import createKeywords
from Products.PluggableAuthService.utils import createViewName
from Products.PluggableAuthService.PluggableAuthService import \
        _SWALLOWABLE_PLUGIN_EXCEPTIONS
from Products.PluggableAuthService.interfaces.plugins import \
    IRolesPlugin, IPropertiesPlugin, IGroupEnumerationPlugin

from Products.LDAPUserFolder.LDAPDelegate import filter_format as _filter_format
from Products.LDAPUserFolder.utils import GROUP_MEMBER_MAP, encoding, guid2string
from Products.PlonePAS.plugins.group import PloneGroup
from zope.annotation.interfaces import IAnnotations
from zope.globalrequest import getRequest

logger = logging.getLogger("PloneLDAP")
prefetch_logger = logger.getChild('prefetch')


class PloneLDAPPluginBaseMixin:
    security = ClassSecurityInfo()

    security.declarePrivate("_getUser")
    def _getUser(self, uid):
        """Utility method to get a user by userid."""

        acl = self._getLDAPUserFolder()
        if acl is not None:
            return acl.getUserById(uid)
        return None

    # The following _ methods gracefuly adapted from PlonePAS.group.GroupManager
    security.declarePrivate('_createGroup')
    def _createGroup(self, plugins, group_id, name):
        """ Create group object. For users, this can be done with a
        plugin, but I don't care to define one for that now. Just uses
        PloneGroup.  But, the code's still here, just commented out.
        This method based on PluggableAuthervice._createUser
        """

        #factories = plugins.listPlugins(IUserFactoryPlugin)

        #for factory_id, factory in factories:

        #    user = factory.createUser(user_id, name)

        #    if user is not None:
        #        return user.__of__(self)

        return PloneGroup(group_id, name).__of__(self)

    security.declarePrivate('_findGroup')
    def _findGroup(self, plugins, group_id, title=None, request=None):
        """ group_id -> decorated_group
        This method based on PluggableAuthService._findGroup
        """

        # See if the group can be retrieved from the cache
        view_name = '_findGroup-%s' % group_id
        keywords = {'group_id': group_id,
                    'title': title}
        group = self.ZCacheable_get(view_name=view_name,
                                    keywords=keywords,
                                    default=None)

        if group is None:

            group = self._createGroup(plugins, group_id, title)

            propfinders = plugins.listPlugins(IPropertiesPlugin)
            for propfinder_id, propfinder in propfinders:

                data = propfinder.getPropertiesForUser(group, request)
                if data:
                    group.addPropertysheet(propfinder_id, data)

            groups = self._getPAS()._getGroupsForPrincipal(group, request,
                                                           plugins=plugins)
            group._addGroups(groups)

            rolemakers = plugins.listPlugins(IRolesPlugin)

            for rolemaker_id, rolemaker in rolemakers:

                roles = rolemaker.getRolesForPrincipal(group, request)

                if roles:
                    group._addRoles(roles)

            group._addRoles(['Authenticated'])

            # Cache the group if caching is enabled
            base_group = aq_base(group)
            if getattr(base_group, '_p_jar', None) is None:
                self.ZCacheable_set(base_group, view_name=view_name,
                                    keywords=keywords)

        return group

    security.declarePrivate('_verifyGroup')
    def _verifyGroup(self, plugins, group_id=None, title=None):

        """ group_id -> boolean
        This method based on PluggableAuthService._verifyUser
        """
        criteria = {}

        if group_id is not None:
            criteria['id'] = group_id
            criteria['exact_match'] = True

        if title is not None:
            criteria['title'] = title

        if criteria:
            view_name = createViewName('_verifyGroup', group_id)
            cached_info = self.ZCacheable_get(view_name=view_name,
                                              keywords=criteria,
                                              default=None)

            if cached_info is not None:
                return cached_info

            enumerators = plugins.listPlugins(IGroupEnumerationPlugin)

            for enumerator_id, enumerator in enumerators:
                try:
                    info = enumerator.enumerateGroups(**criteria)

                    if info:
                        id = info[0]['id']
                        # Put the computed value into the cache
                        self.ZCacheable_set(id, view_name=view_name,
                                            keywords=criteria)
                        return id

                except _SWALLOWABLE_PLUGIN_EXCEPTIONS:
                    logger.exception(
                        'PluggableAuthService: GroupEnumerationPlugin '
                        '%s error', enumerator_id)

        return 0

    @property
    def prefetched_groups(self):
        key = '{}-prefetched-groups'.format(__name__)
        return IAnnotations(getRequest()).setdefault(key, {})

    security.declarePrivate('prefetchGroupsByIds')
    def prefetchGroupsByIds(self, ids):
        logger = prefetch_logger
        logger.debug("groups: %s", ids)

        id_attr = self.groupid_attr
        if id_attr != 'cn':
            logger.warn('Skipping prefetch, for now only "cn" is support as groupid_attr')
            return

        # it might be enough to consult one of the caches
        def uncached(id):
            if self.prefetched_groups.get(id):
                return False

            # in here
            if self.ZCacheable_get(
                    view_name=createViewName('_verifyGroup', id),
                    keywords=createKeywords(id=id, exact_match=True),
                    default=None):
                logger.debug('ldapmp verifyGroup cached: %s', id)
                return False

            # LDAPMultiPlugins
            if self.ZCacheable_get(
                    view_name=self.getId() + '_enumerateGroups',
                    keywords={'id': id,
                              'sort_by': None,
                              'exact_match': True,
                              'max_results': None},
                    default=None):
                logger.debug('ldapmp enumeratGroups cached: %s', id)
                return False

            return True

        ids = filter(uncached, ids)
        logger.debug("remaining after cache  %s", ids)

        if not ids:
            return
        luf = self._getLDAPUserFolder()
        if luf is None:
            return

        # filter_format does not work for objectGUID, according to LUF
        filter_format = (lambda fmt, x: fmt % (x[0], guid2string(x[1]))) \
            if id_attr == 'objectGUID' else _filter_format
        search_str = '(&(|{ids})(|{ocs}))'.format(
            ids=''.join(filter_format('(%s=%s)',
                                      (id_attr, id.encode(encoding))) for id in ids),
            ocs=''.join(filter_format('(%s=%s)', ('objectClass', oc))
                                      for oc in GROUP_MEMBER_MAP.keys())
        )
        search = luf._delegate.search(base=luf.groups_base,
                                      scope=luf.groups_scope,
                                      attrs=(),
                                      filter=search_str)
        if search['exception']:
            logger.warn('Exception (%s)', search['exception'])
            logger.warn('searchstring "%s"', search_str)

        searchGroups_out = ({k: v[0] for k, v in x.items() if len(v) > 0}
                            for x in search['results'])

        plugin_id = self.getId()
        # enable negative prefetch caching
        self.prefetched_groups.update(zip(ids, (False for i in range(len(ids)))))
        self.prefetched_groups.update(
            (x[id_attr], dict(pluginid=plugin_id, id=x[id_attr], **x))
            for x in searchGroups_out if x)

    security.declarePrivate('prefetchUsersByIds')
    def prefetchUsersByIds(self, ids):
        logger = prefetch_logger
        logger.debug("users: %s", ids)
        luf = self._getLDAPUserFolder()
        if luf is None:
            return

        def uncached(id):
            if self.ZCacheable_get(
                    view_name=self.getId() + '_enumerateUsers',
                    keywords={'id': id,
                              'login': None,
                              'sort_by': None,
                              'exact_match': True,
                              'max_results': None},
                    default=None):
                logger.debug('ldapmp enumerateUsers cached: %s', id)
                return False

            return True

        ids = filter(uncached, ids)
        logger.debug("remaining after cache  %s", ids)

        if not ids:
            return
        luf.prefetchUsersByIds(ids)


InitializeClass(PloneLDAPPluginBaseMixin)
