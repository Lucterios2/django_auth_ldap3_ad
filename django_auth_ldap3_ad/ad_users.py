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

"""
scripts mainly from:
https://mespotesgeek.fr/fr/python-et-utilisateurs-active-directory/
"""

from django.conf import settings
from ldap3 import Server, ServerPool, Connection, FIRST, SYNC, SIMPLE, MODIFY_REPLACE
from django.core.exceptions import ImproperlyConfigured
import logging

logger = logging.getLogger(__name__)


class Aduser:
    def __init__(self):
        self.pool = None
        self.con = None
        self.connect()

    def connect(self):
        # check configuration
        if not (hasattr(settings, 'LDAP_SERVERS') and hasattr(settings, 'LDAP_BIND_USER') and
                hasattr(settings, 'LDAP_BIND_PWD') and hasattr(settings, 'LDAP_AD_DOMAIN') and
                hasattr(settings, 'LDAP_USER_OBJECTCLASS')
                ):
            raise ImproperlyConfigured()

        # first: build server pool from settings
        if self.pool is None:
            self.pool = ServerPool(None, pool_strategy=FIRST, active=True)
            for srv in settings.LDAP_SERVERS:
                # Only add servers that supports SSL, impossible to make changes without
                if srv['use_ssl']:
                    server = Server(srv['host'], srv['port'], srv['use_ssl'])
                    self.pool.add(server)

        # then, try to connect with user/pass from settings
        self.con = Connection(self.pool, auto_bind=True, client_strategy=SYNC, user=settings.LDAP_BIND_USER,
                              password=settings.LDAP_BIND_PWD, authentication=SIMPLE, check_names=True)

    def create_ad_user(self, user_dn, firstname, lastname, samaccountname, mail=None, description=None):
        if self.con is None:
            self.connect()

        user_attribs = {
            'cn': lastname,
            'givenName': firstname,
            'displayName': '%s %s' % (firstname, lastname),
            'sAMAccountName': samaccountname,
            'userAccountControl': '514',
        # 514 will set user account to disabled, 512 is enable but can't create directly
            'userPrincipalName': '%s@%s' % (samaccountname, settings.LDAP_AD_DOMAIN)
        }

        if mail is not None:
            user_attribs['mail'] = mail
        if description is not None:
            user_attribs['description'] = description

        self.con.add(
            user_dn,
            settings.LDAP_USER_OBJECTCLASS,
            user_attribs
        )

    def activate_ad_user(self, user_dn):
        if self.con is None:
            self.connect()

        self.con.modify(
            user_dn,
            {
                "userAccountControl": [(MODIFY_REPLACE, ['512'])]
            }
        )

    def update_password_ad_user(self, user_dn, newpassword):
        if self.con is None:
            self.connect()

        unicode_pass = ("\"" + newpassword + "\"").decode("utf-8", "strict")
        password_value = unicode_pass.encode("utf-16-le")

        self.con.modify(
            user_dn,
            {
                "unicodePwd": [(MODIFY_REPLACE, [password_value])]
            }
        )
