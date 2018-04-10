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

logger = logging.getLogger(__name__)


class LDAPUser:
    def __init__(self):
        self.mode = 'AD'
        if hasattr(settings, 'LDAP_ENGINE'):
            self.mode = settings.LDAP_ENGINE

    def create_user(self, user_dn, firstname, lastname, login, mail=None, description=None):
        if self.mode == 'AD':
            adu = Aduser()
            return adu.create_ad_user(user_dn, firstname, lastname, login, mail, description)
        else:
            return False

    def update_ad_user(self, user_dn, attributes):
        if self.mode == 'AD':
            adu = Aduser()
            return adu.update_ad_user(user_dn, attributes)
        else:
            return False

    def activate_ad_user(self, user_dn, never_expires=False):
        if self.mode == 'AD':
            adu = Aduser()
            return adu.activate_ad_user(user_dn, never_expires)
        else:
            return False

    def update_password_ad_user(self, user_dn, newpassword):
        if self.mode == 'AD':
            adu = Aduser()
            return adu.update_password_ad_user(user_dn, newpassword)
        else:
            return False

    def deactivate_ad_user(self, user_dn, never_expires=False):
        if self.mode == 'AD':
            adu = Aduser()
            return adu.deactivate_ad_user(user_dn, never_expires)
        else:
            return False
