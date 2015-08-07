# -*- coding: utf-8 -*-
"""
Basic setting module to declare a new Lucterios appli

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

from django.conf import settings
from django.contrib.auth.models import User, Group
from ldap3 import Server, ServerPool, Connection, FIRST, SYNC, SIMPLE
from django.core.exceptions import ObjectDoesNotExist


class LDAP3ADBackend(object):
    """
    Authenticate against Activie directory or other LDAP server

    Once the user authenticated and retrieved from LDAP, the corresponding local user is created

    It's groups are also examined to enable auto binding to local django groups.
    """

    def authenticate(self, username=None, password=None):
        # first: build server pool from settings
        pool = ServerPool(None, pool_strategy=FIRST, active=True)
        for srv in settings.LDAP_SERVERS:
            server = Server(srv['host'], srv['port'], srv['use_ssl'])
            pool.add(server)

        # then, try to connect with user/pass from settings
        con = Connection(pool, auto_bind=True, client_strategy=SYNC, user=settings.LDAP_BIND_USER,
                         password=settings.LDAP_BIND_PWD, authentication=SIMPLE, check_names=True)

        # search for the desired user
        con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_USER_SEARCH_FILTER % username,
                   attributes=list(settings.LDAP_ATTRIBUTES_MAP.values()))
        if con.result['result'] == 0 and len(con.response) > 0 and 'dn' in con.response[0].keys():
            user_dn = con.response[0]['dn']
            user_attribs = con.response[0]['attributes']
            con.unbind()

            # now, we know the dn of the user, we try a simple bind. This way,
            # the LDAP checks the password with it's algorithm and the active state of the user in one test
            con = Connection(pool, user=user_dn, password=password)
            if con.bind():
                usr = None
                try:
                    # try to retrieve user from database and update it
                    usr = User.objects.get(username=username)
                except User.DoesNotExist:
                    # user does not exist in database already, create it
                    usr = User()

                usr = self.update_user(usr, user_attribs)
                usr.set_password(password)
                usr.save()

                # check for groups membership
                # first cleanup
                usr.is_superuser = False
                usr.is_staff = False
                usr.save()
                for grp in Group.objects.all():
                    grp.user_set.remove(usr)
                    grp.save()

                # then re-fill
                con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_GROUPS_SEARCH_FILTER,
                           attributes=['cn', settings.LDAP_GROUP_MEMBER_ATTRIBUTE])
                if len(con.response) > 0:
                    for resp in con.response:
                        if 'attributes' in resp and settings.LDAP_GROUP_MEMBER_ATTRIBUTE in resp['attributes'] \
                                and user_dn in resp['attributes'][settings.LDAP_GROUP_MEMBER_ATTRIBUTE]:
                            # special super user group
                            if resp['dn'] in settings.LDAP_SUPERUSER_GROUPS:
                                usr.is_superuser = True
                            # special staff group
                            if resp['dn'] in settings.LDAP_STAFF_GROUPS:
                                usr.is_staff = True
                            # other groups membership
                            for grp in settings.LDAP_GROUPS_MAP.keys():
                                if resp['dn'] == settings.LDAP_GROUPS_MAP[grp]:
                                    try:
                                        group = Group.objects.get(name=grp)
                                        group.user_set.add(usr)
                                        group.save()
                                    except ObjectDoesNotExist:
                                        pass
                usr.save()
                return usr

        con.unbind()
        return None

    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    def update_user(self, user, attributes):
        if user is not None:
            for attr in settings.LDAP_ATTRIBUTES_MAP.keys():
                if settings.LDAP_ATTRIBUTES_MAP[attr] in attributes \
                        and len(attributes[settings.LDAP_ATTRIBUTES_MAP[attr]]) >= 1 \
                        and hasattr(user, attr):
                    setattr(user, attr, attributes[settings.LDAP_ATTRIBUTES_MAP[attr]][0])
        return user
