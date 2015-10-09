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
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from django.shortcuts import get_object_or_404


class LDAP3ADBackend(object):
    """
    Authenticate against Activie directory or other LDAP server

    Once the user authenticated and retrieved from LDAP, the corresponding local user is created

    It's groups are also examined to enable auto binding to local django groups.
    """

    # server pool
    pool = None

    # do we use LDAP Groups?
    use_groups = False

    @staticmethod
    def init_and_get_ldap_user(username):
        # check configuration
        if not (hasattr(settings, 'LDAP_SERVERS') and hasattr(settings, 'LDAP_BIND_USER')
                and hasattr(settings, 'LDAP_BIND_PWD') and hasattr(settings, 'LDAP_SEARCH_BASE')
                and hasattr(settings, 'LDAP_USER_SEARCH_FILTER') and hasattr(settings, 'LDAP_ATTRIBUTES_MAP')):

            raise ImproperlyConfigured()

        # as first release of the module does not have this parameter, default is to set it true to keep the same
        # comportment after updates.
        if hasattr(settings, 'LDAP_USE_LDAP_GROUPS') and isinstance(settings.LDAP_USE_LDAP_GROUPS, bool):
            LDAP3ADBackend.use_groups = settings.LDAP_USE_LDAP_GROUPS
        else:
            LDAP3ADBackend.use_groups = True

        if LDAP3ADBackend.use_groups and not (hasattr(settings, 'LDAP_GROUPS_SEARCH_FILTER')
                                              and hasattr(settings, 'LDAP_GROUP_MEMBER_ATTRIBUTE')
                                              and hasattr(settings, 'LDAP_GROUPS_MAP')):
            raise ImproperlyConfigured()

        # first: build server pool from settings
        if LDAP3ADBackend.pool is None:
            LDAP3ADBackend.pool = ServerPool(None, pool_strategy=FIRST, active=True)
            for srv in settings.LDAP_SERVERS:
                server = Server(srv['host'], srv['port'], srv['use_ssl'])
                LDAP3ADBackend.pool.add(server)

        # then, try to connect with user/pass from settings
        con = Connection(LDAP3ADBackend.pool, auto_bind=True, client_strategy=SYNC, user=settings.LDAP_BIND_USER,
                         password=settings.LDAP_BIND_PWD, authentication=SIMPLE, check_names=True)

        # search for the desired user
        user_dn = None
        user_attribs = None
        con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_USER_SEARCH_FILTER % username,
                   attributes=list(settings.LDAP_ATTRIBUTES_MAP.values()))
        if con.result['result'] == 0 and len(con.response) > 0 and 'dn' in con.response[0].keys():
            user_dn = con.response[0]['dn']
            user_attribs = con.response[0]['attributes']
        con.unbind()
        return user_dn, user_attribs

    @staticmethod
    def authenticate(username=None, password=None):
        if username is None:
            return None

        user_dn, user_attribs = LDAP3ADBackend.init_and_get_ldap_user(username)
        if user_dn is not None and user_attribs is not None:
            # now, we know the dn of the user, we try a simple bind. This way,
            # the LDAP checks the password with it's algorithm and the active state of the user in one test
            con = Connection(LDAP3ADBackend.pool, user=user_dn, password=password)
            if con.bind():
                try:
                    # try to retrieve user from database and update it
                    usr = User.objects.get(username__iexact=username)
                except User.DoesNotExist:
                    # user does not exist in database already, create it
                    usr = User()

                # update existing or new user with LDAP data
                usr = LDAP3ADBackend.update_user(usr, user_attribs)
                usr.set_password(password)
                usr.save()

                # if we want to use LDAP group membership:
                if LDAP3ADBackend.use_groups:
                    # check for groups membership
                    # first cleanup
                    alter_superuser_membership = False
                    if hasattr(settings, 'LDAP_SUPERUSER_GROUPS') and isinstance(settings.LDAP_SUPERUSER_GROUPS, list)\
                       and len(settings.LDAP_SUPERUSER_GROUPS) > 0:
                        usr.is_superuser = False
                        alter_superuser_membership = True

                    alter_staff_membership = False
                    if hasattr(settings, 'LDAP_STAFF_GROUPS') and isinstance(settings.LDAP_STAFF_GROUPS, list)\
                       and len(settings.LDAP_STAFF_GROUPS) > 0:
                        usr.is_staff = False
                        alter_staff_membership = True

                    usr.save()
                    for grp in Group.objects.all():
                        grp.user_set.remove(usr)
                        grp.save()

                    # then re-fill
                    con.search(settings.LDAP_GROUPS_SEARCH_BASE if hasattr(settings, 'LDAP_GROUPS_SEARCH_BASE')
                               else settings.LDAP_SEARCH_BASE,
                               settings.LDAP_GROUPS_SEARCH_FILTER,
                               attributes=['cn', settings.LDAP_GROUP_MEMBER_ATTRIBUTE])
                    if len(con.response) > 0:
                        for resp in con.response:
                            if 'attributes' in resp and settings.LDAP_GROUP_MEMBER_ATTRIBUTE in resp['attributes'] \
                                    and user_dn in resp['attributes'][settings.LDAP_GROUP_MEMBER_ATTRIBUTE]:
                                # special super user group
                                if alter_superuser_membership:
                                    if resp['dn'] in settings.LDAP_SUPERUSER_GROUPS:
                                        usr.is_superuser = True
                                # special staff group
                                if alter_staff_membership:
                                    if resp['dn'] in settings.LDAP_STAFF_GROUPS:
                                        usr.is_staff = True
                                # other groups membership
                                for grp in settings.LDAP_GROUPS_MAP.keys():
                                    if resp['dn'] == settings.LDAP_GROUPS_MAP[grp]:
                                        try:
                                            print(grp)
                                            group = Group.objects.get(name=grp)
                                            group.user_set.add(usr)
                                            group.save()
                                        except ObjectDoesNotExist:
                                            pass
                    usr.save()

                con.unbind()

                # force reload the user to apply rights
                return User.objects.get(pk=usr.pk)

            con.unbind()
        return None

    @staticmethod
    def get_user(user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

    @staticmethod
    def update_user(user, attributes):
        if user is not None:
            for attr in settings.LDAP_ATTRIBUTES_MAP.keys():
                if settings.LDAP_ATTRIBUTES_MAP[attr] in attributes \
                        and len(attributes[settings.LDAP_ATTRIBUTES_MAP[attr]]) >= 1 \
                        and hasattr(user, attr):
                    setattr(user, attr, attributes[settings.LDAP_ATTRIBUTES_MAP[attr]][0])
        return user
    #
    # @staticmethod
    # def change_password(username, old_password, new_password):
    #     user_dn, user_attribs = LDAP3ADBackend.init_and_get_ldap_user(username)
    #     if user_dn is not None:
    #         print(user_dn)
    #         con = Connection(LDAP3ADBackend.pool, user=user_dn, password=old_password)
    #         if con.bind():
    #             con.extend.standard.modify_password(user_dn, old_password, new_password.encode('utf-8'), 'md5')
    #             return True
    #
    #         return False
