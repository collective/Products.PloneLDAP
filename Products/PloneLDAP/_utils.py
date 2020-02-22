# coding=utf-8
import zope.deferredimport

zope.deferredimport.initialize()

zope.deferredimport.deprecated(
    "Import from Products.CMFPlone.utils instead",
    safe_unicode='Products.CMFPlone.utils:safe_unicode',
)
