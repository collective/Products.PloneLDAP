try:
    from hashlib import sha1 as sha_new
except ImportError:
    from sha import new as sha_new
from itertools import chain
from AccessControl.Permissions import manage_users as ManageUsers
from AccessControl.PermissionRole import PermissionRole
from Products.LDAPUserFolder.LDAPDelegate import filter_format
from Products.LDAPUserFolder.LDAPUser import LDAPUser
from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder
from Products.LDAPUserFolder.LDAPUserFolder import _marker, logger
from Products.LDAPUserFolder.utils import GROUP_MEMBER_ATTRIBUTES
from Products.LDAPUserFolder.utils import GROUP_MEMBER_MAP
from Products.LDAPUserFolder.utils import guid2string
from Products.LDAPUserFolder.utils import to_utf8
from zope.annotation.interfaces import IAnnotations
from zope.globalrequest import getRequest


prefetch_logger = logger.getChild('prefetch')


def get_prefetched_users():
    key = '{}-prefetched-users'.format(__name__)
    return IAnnotations(getRequest()).setdefault(key, {})


def prefetchUsersByIds(self, ids):
    prefetch_logger.info("users: %s", ids)

    id_attr = self._uid_attr
    if id_attr == 'dn':
        prefetch_logger.warn('Prefetching not supported for uid_attr dn')
        return

    prefetched_users = get_prefetched_users()
    def uncached(id):
        if prefetched_users.get(id):
            return False

        if self._cache('negative') \
              .get('%s:%s:%s' % \
                   (self._uid_attr, id, sha_new('').hexdigest())):
            prefetch_logger.info('discarding negatively cached: %s', id)
            return False

        if self._cache('anonymous').get(id):
            prefetch_logger.info('discarding anonymously cached: %s', id)
            return False

        return True

    ids = filter(uncached, ids)
    prefetch_logger.info("remaining after cache  %s", ids)
    if not ids:
        return

    login_attr = self._login_attr
    mapped_attrs = self.getMappedUserAttrs()
    multivalued_attrs = self.getMultivaluedUserAttrs()
    def make_ldap_user(id, roles, dn, user_attrs, groups):
        # XXX: shall we handle/use LUF's negative/anonymous caches here?
        # a separate per request prefetch cache might not be
        # necessary but is a safe assumption
        if dn is None:
            return
        if user_attrs is None:
            return

        login_name = user_attrs.get(login_attr, '')
        if login_attr != 'dn' and len(login_name) > 0:
            if id_attr == login_attr:
                login_name = (x for x in login_name
                              if id.strip().lower() == x.lower()).next()
            else:
                login_name = login_name[0]
        elif len(login_name) == 0:
            return

        return LDAPUser(id,
                        login_name,
                        'undef',
                        roles or [],
                        [],
                        dn,
                        user_attrs,
                        mapped_attrs,
                        multivalued_attrs,
                        ldap_groups=groups)

    filter_fmt = (lambda fmt, x: fmt % (x[0], guid2string(x[1]))) \
        if id_attr == 'objectGUID' else filter_format
    search_str = '(&(|{ids})(|{ocs}))'.format(
        ids=''.join(filter_fmt(
            '(%s=%s)', (id_attr, to_utf8(id))) for id in ids),
        ocs=''.join(filter_format('(%s=%s)', ('objectClass', oc))
                    for oc in self._user_objclasses)
    )
    extra_filter = self.getProperty('_extra_user_filter')
    if extra_filter:
        search_str = '(&({})({}))'.format(search_str, extra_filter)
    if self._binduid_usage > 0:
        bind_dn = self._binduid
        bind_pwd = self._bindpwd
    else:
        bind_dn = bind_pwd = ''
    known_attrs = self.getSchemaConfig().keys()
    search = self._delegate.search(base=self.users_base,
                                   scope=self.users_scope,
                                   filter=search_str,
                                   attrs=known_attrs,
                                   bind_dn=bind_dn,
                                   bind_pwd=bind_pwd)
    if search['size'] == 0 or search['exception']:
        return

    def make_user_info(user_attrs):
        dn = user_attrs.get('dn')
        utf8_dn = to_utf8(dn)
        return utf8_dn, user_attrs

    user_infos = [make_user_info(x) for x in search['results']]
    dns = [dn for dn, attrs in user_infos]
    gsearch_str = '(|{})'.format(''.join(
        '(&{}{})'.format(
            filter_format('(objectClass=%s)', (oc,)),
            filter_format('(%s=%s)', (member_attr, dn)),
        )
        for oc, member_attr in GROUP_MEMBER_MAP.items()
        for dn in dns))
    gscope = self._delegate.getScopes()[self.groups_scope]
    gsearch = self._delegate.search(base=self.groups_base,
                                    scope=gscope,
                                    filter=gsearch_str,
                                    attrs=['cn'] + list(GROUP_MEMBER_ATTRIBUTES),
                                    bind_dn=bind_dn,
                                    bind_pwd=bind_pwd)
    groups = dict()
    for attrs in gsearch['results']:
        cn = attrs['cn'][0]
        for attr in GROUP_MEMBER_ATTRIBUTES:
            for user_dn in attrs.get(attr, ()):
                groups.setdefault(user_dn, []).append(cn)
    _mapRoles = self._mapRoles
    _roles = self._roles
    users = ((id, make_ldap_user(id,
                                 _mapRoles(groups.get(dn, [])) + _roles,
                                 dn,
                                 user_attrs,
                                 groups.get(dn, [])))
             for id, dn, user_attrs in ((user_attrs[id_attr][0], dn, user_attrs)
                                        for dn, user_attrs in user_infos))
    prefetched_users.update(zip(ids, (False for i in range(len(ids)))))
    prefetched_users.update(chain.from_iterable(
        ((id, user), (user._dn, user))
        for id, user in users
        if user is not None
    ))
LDAPUserFolder.prefetchUsersByIds = prefetchUsersByIds
LDAPUserFolder.prefetchUsersByIds__roles__ = \
    PermissionRole(ManageUsers, ('Manager',))


_orig_getUserById = LDAPUserFolder.getUserById
def getUserById(self, id, default=_marker):
    user = get_prefetched_users().get(id)
    if user is False:
        return
    elif user is not None:
        return user

    return _orig_getUserById(self, id, default)
LDAPUserFolder.getUserById = getUserById
