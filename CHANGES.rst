Changes
=======

2.0.0a1 (2023-05-03)
--------------------

* Fix setProperties to not set a None value.
  [allusa]

* Fix typo for custom extra_user_filter.
  See comments below about "When creating an Active Directory plugin
  ... ignore disabled or non-user accounts ..."
  [mamico]

* Remove duplicate line with no effect.
  [saily]

* Support mapping LDAP groups to Plone roles via the Users and Groups
  control panel.
  [adaugherity]

* Zope 4 compatibility: Replaced broken imports of InitializeClass.
  [reinhardt]


1.2 (2012-11-30)
----------------

* Only the LDAP plugin implements IGroupManagement, not the
  ActiveDirectory plugin.  This is for adding, removing and editing
  groups.

* Code moved to https://github.com/collective/Products.PloneLDAP

* Let only the LDAP multi plugin implement the IGroupCapability
  interface (add a user to a group or remove a user from a group).
  Previously the AD multi plugin claimed to implement this too, but it
  lacked the required methods, so this could lead to tracebacks.  We
  could instead add those methods via the mixin class, but but this
  gave other tracebacks (in removePrincipalFromGroup) when I tried it
  in one AD setup.

* Fix setProperties to split value into lines if lines property
  receives a string instead of an iterable.

* When creating an Active Directory plugin configure LDAPUserFolder
  to ignore disabled or non-user accounts. This requires
  Products.LDAPUserFolder 2.11 or later.


1.1 (2008-06-10)
----------------

* Switch license to ZPL.

* Depend on the Products.LDAPMultiPlugins and Products.LDAPUserFolder.

* Switch to egg-only releases from now on.


1.0
---

* Hide LDAPUserFolder from the list of Add-On Products since installing it
  will kill your Plone site. Plone 3.0 only.

* Fix incorrect security declaration for doDeleteUser


1.0rc3
------

* Fix getGroupMembers to return user ids instead of login names for group
  members. This broke group membership listing in environments where userid
  and login name differ (for example AD environments). Thanks to Netcentric
  for discovering this and helping me fix it.

* Add some protection against invalid (None) results of group related
  searches.

* Add more information about the capabilities and caveats of LDAP use in Plone.


1.0rc2
------

* Improve the documentation.

* Add missing cache invalidation for role management and user deletion.

* Fix updating of single-valued member properties.

* Use a different method to get the containing LDAPUserFolder. This allows
  use of PloneLDAP outside of a CMF site.


1.0rc1
------

* Fix setting of object classes when creating a new plugin instance.

* Fix member property sheets: RAM caching does not like it when you try
  to store non-pickleable data.

