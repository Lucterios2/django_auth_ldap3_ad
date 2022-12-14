# -*- coding: utf-8 -*-
"""
@author: Pierre-Olivier VERSCHOORE
@organization: sd-libre.fr
@contact: info@sd-libre.fr
@copyright: 2015 sd-libre.fr
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

from django.conf import settings

from django_auth_ldap3_ad.ad_users import Aduser
from django_auth_ldap3_ad.openldap_users import OpenLDAPUser
from django_auth_ldap3_ad.abstract_users import AbstractUser

logger = logging.getLogger(__name__)


class UserManager:
    def __init__(self):
        self.mode = 'AD'
        if hasattr(settings, 'LDAP_ENGINE'):
            self.mode = settings.LDAP_ENGINE

    def create_user(self, user_dn, firstname, lastname, login, mail=None, description=None):
        if self.mode == 'AD':
            with Aduser() as adu:
                return adu.create_ad_user(user_dn, firstname, lastname, login, mail, description)
        else:
            with OpenLDAPUser() as ldapu:
                return ldapu.create_record(user_dn, givenName=firstname, sn=lastname, cn=login, mail=mail, description=description)

    def update_user(self, user_dn, attributes):
        with AbstractUser.factory() as user:
            return user.update_record(user_dn, **attributes)

    def update_password_user(self, user_dn, newpassword):
        with AbstractUser.factory() as user:
            return user.update_password(user_dn, newpassword)

    def activate_user(self, user_dn, never_expires=False):
        if self.mode == 'AD':
            with Aduser() as adu:
                return adu.activate_ad_user(user_dn, never_expires)
        else:
            return False

    def deactivate_user(self, user_dn, never_expires=False):
        if self.mode == 'AD':
            with Aduser() as adu:
                return adu.deactivate_ad_user(user_dn, never_expires)
        else:
            return False
