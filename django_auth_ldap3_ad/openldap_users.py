# -*- coding: utf-8 -*-
"""
@author: Laurent Gay
@organization: sd-libre.fr
@contact: info@sd-libre.fr
@copyright: 2022 sd-libre.fr
@license: This file is part of Lucterios.

Lucterios is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Lucterios is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Lucterios.  If not, see <http://www.gnu.org/licenses/>.
"""

import logging

from ldap3.utils.hashed import hashed, HASHED_SALTED_SHA

from django.conf import settings

from django_auth_ldap3_ad.abstract_users import AbstractUser


logger = logging.getLogger(__name__)


class OpenLDAPUser(AbstractUser):

    OBJECT_CLASS = 'objectClass'

    @classmethod
    def can_used(cls):
        return hasattr(settings, 'LDAP_ENGINE') and (settings.LDAP_ENGINE == 'OpenLDAP') and AbstractUser.can_used()

    def update_password(self, user_dn, newpassword):
        return self.update_record(user_dn, userPassword=hashed(HASHED_SALTED_SHA, newpassword))

    def create_record(self, user_dn, **user_attribs):
        if self.OBJECT_CLASS not in user_attribs:
            search_filter = getattr(settings, "LDAP_USER_SEARCH_FILTER", "(objectClass=inetOrgPerson)")
            pos_begin = search_filter.find(self.OBJECT_CLASS)
            pos_end = search_filter.find(')', pos_begin)
            if (pos_begin != -1) and (pos_end != -1):
                user_attribs['objectClass'] = [search_filter[pos_begin + len(self.OBJECT_CLASS) + 1:pos_end]]
            else:
                user_attribs['objectClass'] = ['inetOrgPerson']
        if 'cn' not in user_attribs:
            user_attribs['cn'] = "%s %s" % (user_attribs['givenName'], user_attribs['sn']),
        return AbstractUser.create_record(self, user_dn, **user_attribs)
