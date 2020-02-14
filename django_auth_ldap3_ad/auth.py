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
import os
import string
import random

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from ldap3 import Server, ServerPool, Connection, FIRST, SYNC, SIMPLE, NTLM
from six import string_types
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from datetime import datetime
import logging
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.backends import ModelBackend

logger = logging.getLogger(__name__)


def user_logged_in_handler(sender, request, user, **kwargs):
    """
    in authenticate method, the request is not available so, the session engine is either not available.
    By using this signal binding, we can get the special attributes added to the object by the authenticate
    method and save them in the current session
    """
    if 'dn' in user.__dict__ and user.dn is not None:
        request.session['LDAP_USER_DN'] = user.dn
    if 'bu' in user.__dict__ and user.bu is not None:
        request.session['LDAP_USER_BU'] = user.bu


user_logged_in.connect(user_logged_in_handler)


def create_password():
    # generate password
    chars = string.ascii_letters + string.digits + '!@#$%&*'
    random.seed = (os.urandom(1024))
    families = 0
    passwd = ''
    while families < 3:
        passwd = ''.join(random.choice(chars) for i in range(10))
        lowercase = [c for c in passwd if c.islower()]
        uppercase = [c for c in passwd if c.isupper()]
        digits = [c for c in passwd if c.isdigit()]
        ponctuation = [c for c in passwd if not c.isalnum()]

        families = 1 if len(lowercase) > 0 else 0
        families += 1 if len(uppercase) > 0 else 0
        families += 1 if len(digits) > 0 else 0
        families += 1 if len(ponctuation) > 0 else 0

        logger.debug("PROPOSITION PASSWORD: %s" % passwd)
        logger.debug("FAMILIES: %s" % families)

    return passwd


class LDAP3ADBackend(ModelBackend):
    """
    Authenticate against Active directory or other LDAP server

    Once the user authenticated and retrieved from LDAP, the corresponding local user is created

    It's groups are also examined to enable auto binding to local django groups.
    """

    # server pool
    pool = None

    # do we use LDAP Groups?
    use_groups = False

    def init_and_get_ldap_user(self, username):
        if username is None or username == '':
            return None, None

        # add LDAP_BIND_PASSWORD as password field
        password_field = 'LDAP_BIND_PWD' if hasattr(settings, 'LDAP_BIND_PWD') else 'LDAP_BIND_PASSWORD'

        # check configuration
        if not (hasattr(settings, 'LDAP_SERVERS') and hasattr(settings, 'LDAP_BIND_USER') and
                hasattr(settings, password_field) and hasattr(settings, 'LDAP_SEARCH_BASE') and
                hasattr(settings, 'LDAP_USER_SEARCH_FILTER') and hasattr(settings, 'LDAP_ATTRIBUTES_MAP')):
            raise ImproperlyConfigured()

        # as first release of the module does not have this parameter, default is to set it true to keep the same
        # comportment after updates.
        if hasattr(settings, 'LDAP_USE_LDAP_GROUPS') and isinstance(settings.LDAP_USE_LDAP_GROUPS, bool):
            LDAP3ADBackend.use_groups = settings.LDAP_USE_LDAP_GROUPS
        else:
            LDAP3ADBackend.use_groups = True

        if LDAP3ADBackend.use_groups and not (hasattr(settings, 'LDAP_GROUPS_SEARCH_FILTER') and
                                              hasattr(settings, 'LDAP_GROUP_MEMBER_ATTRIBUTE') and
                                              hasattr(settings, 'LDAP_GROUPS_MAP')):
            raise ImproperlyConfigured()

        # LDAP_IGNORED_LOCAL_GROUPS is a list of local Django groups that must be kept.
        if (hasattr(settings, 'LDAP_IGNORED_LOCAL_GROUPS') and
                not isinstance(settings.LDAP_IGNORED_LOCAL_GROUPS, list)):
            raise ImproperlyConfigured()

        if hasattr(settings, 'LDAP_AUTHENTICATION'):
            authentication = getattr(settings, 'LDAP_AUTHENTICATION')
        else:
            authentication = SIMPLE

        # first: build server pool from settings
        if LDAP3ADBackend.pool is None:
            LDAP3ADBackend.pool = ServerPool(None, pool_strategy=FIRST, active=True)
            for srv in settings.LDAP_SERVERS:
                # from rechie, pullrequest #30
                # check if LDAP_SERVERS settings has set ldap3 `get_info` parameter
                if 'get_info' in srv:
                    server = Server(srv['host'], srv['port'], srv['use_ssl'], get_info=srv['get_info'])
                else:
                    server = Server(srv['host'], srv['port'], srv['use_ssl'])

                LDAP3ADBackend.pool.add(server)

        # then, try to connect with user/pass from settings
        con = Connection(LDAP3ADBackend.pool, auto_bind=True, client_strategy=SYNC, user=settings.LDAP_BIND_USER,
                         password=getattr(settings, password_field) or settings.LDAP_BIND_PASSWORD,
                         authentication=authentication, check_names=True)

        # search for the desired user
        user_dn = None
        user_attribs = None
        con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_USER_SEARCH_FILTER.replace('%s', '{0}').format(username),
                   attributes=list(settings.LDAP_ATTRIBUTES_MAP.values()))
        if con.result['result'] == 0 and len(con.response) > 0 and 'dn' in con.response[0].keys():
            user_dn = con.response[0]['dn']
            user_attribs = con.response[0]['attributes']

            # from rechie, pullrequest #30
            # convert `user_attribs` values to string if the returned value is a list
            for attrib in user_attribs:
                if isinstance(user_attribs[attrib], list):
                    user_attribs[attrib] = user_attribs[attrib][0]
        con.unbind()
        return user_dn, user_attribs

    """
    Authentication method for Django against AD/LDAP
    First, retrieve the user's DN based on it's username
    then, try to authenticate against the LDAP server pool using the DN and password.
    If ok, update user's attributes with LDAP ones and, if configured, update the group list.
    Finally, if setup, adds the minimal group membership common to all users
    """

    def authenticate(self, request, username=None, password=None):
        logger.info("AUDIT BEGIN LOGIN PROCESS FOR: %s AT %s" % (username, datetime.now()))
        if username is None or username == '':
            return None

        # search capacities differs on LDAP engines.
        ldap_engine = 'AD'  # to keep compatibility with previous version
        if hasattr(settings, 'LDAP_ENGINE') and settings.LDAP_ENGINE is not None:
            ldap_engine = settings.LDAP_ENGINE

        user_dn, user_attribs = self.init_and_get_ldap_user(username)
        if user_dn is not None and user_attribs is not None:
            # now, we know the dn of the user, we try a simple bind. This way,
            # the LDAP checks the password with it's algorithm and the active state of the user in one test
            con = Connection(LDAP3ADBackend.pool, user=user_dn, password=password)
            if con.bind():
                logger.info("AUDIT SUCCESS LOGIN FOR: %s AT %s" % (username, datetime.now()))
                user_model = get_user_model()

                """
                We add special attributes only during the authentication process to store user DN & Business Unit
                Those attributes are saved in the current session by the user_logged_in_handler
                """
                user_model.dn = lambda: None
                user_model.bu = lambda: None
                try:
                    # try to retrieve user from database and update it
                    username_field = getattr(settings, 'LDAP_USER_MODEL_USERNAME_FIELD', 'username') 
                    lookup_username = user_attribs[settings.LDAP_ATTRIBUTES_MAP[username_field]]
                    usr = user_model.objects.get(**{"{0}__iexact".format(username_field): lookup_username})
                except user_model.DoesNotExist:
                    # user does not exist in database already, create it
                    usr = user_model()

                # update existing or new user with LDAP data
                self.update_user(usr, user_attribs)
                if hasattr(settings, 'LDAP_OBFUSCATE_PASS') and settings.LDAP_OBFUSCATE_PASS:
                    usr.set_password(create_password())
                else:
                    usr.set_password(password)
                usr.last_login = datetime.now()
                usr.save()

                # if we want to use LDAP group membership:
                if LDAP3ADBackend.use_groups:

                    # if using AD filter groups in result by using groups in the config
                    if ldap_engine == 'AD':
                        # inspired from
                        # https://github.com/Lucterios2/django_auth_ldap3_ad/commit/ce24d4687f85ed12a0c4c796022ae7dcb3ff38e3
                        # by jobec
                        all_ldap_groups = []
                        for group in settings.LDAP_SUPERUSER_GROUPS + settings.LDAP_STAFF_GROUPS + list(
                                settings.LDAP_GROUPS_MAP.values()):
                            all_ldap_groups.append("(distinguishedName={0})".format(group))

                        if len(all_ldap_groups) > 0:
                            settings.LDAP_GROUPS_SEARCH_FILTER = "(&{0}(|{1}))".format(
                                settings.LDAP_GROUPS_SEARCH_FILTER,
                                "".join(all_ldap_groups))
                            # end
                    # if using OpenLDAP, filter groups in search by membership of the user
                    elif ldap_engine == 'OpenLDAP':
                        # add filter on member
                        settings.LDAP_GROUPS_SEARCH_FILTER = "(&%s(member=%s))" % (settings.LDAP_GROUPS_SEARCH_FILTER,
                                                                                   user_dn)
                        # add filter on groups to match
                        all_ldap_groups = []
                        for group in settings.LDAP_SUPERUSER_GROUPS + settings.LDAP_STAFF_GROUPS + list(
                                settings.LDAP_GROUPS_MAP.values()):
                            if "(%s)" % group.split(',')[0] not in all_ldap_groups:
                                all_ldap_groups.append("(%s)" % group.split(',')[0])

                        if len(all_ldap_groups) > 0:
                            settings.LDAP_GROUPS_SEARCH_FILTER = "(&{0}(|{1}))".format(
                                settings.LDAP_GROUPS_SEARCH_FILTER,
                                "".join(all_ldap_groups))

                    logger.info("AUDIT LOGIN FOR: %s AT %s USING LDAP GROUPS" % (username, datetime.now()))
                    # check for groups membership
                    # first cleanup
                    alter_superuser_membership = False
                    if hasattr(settings, 'LDAP_SUPERUSER_GROUPS') and isinstance(settings.LDAP_SUPERUSER_GROUPS, list) \
                            and len(settings.LDAP_SUPERUSER_GROUPS) > 0:
                        usr.is_superuser = False
                        alter_superuser_membership = True

                    alter_staff_membership = False
                    if hasattr(settings, 'LDAP_STAFF_GROUPS') and isinstance(settings.LDAP_STAFF_GROUPS, list) \
                            and len(settings.LDAP_STAFF_GROUPS) > 0:
                        usr.is_staff = False
                        alter_staff_membership = True

                    usr.save()
                    logger.info("AUDIT LOGIN FOR: %s AT %s CLEANING OLD GROUP MEMBERSHIP" % (username, datetime.now()))
                    if hasattr(settings, 'LDAP_IGNORED_LOCAL_GROUPS'):
                        grps = Group.objects.exclude(name__in=settings.LDAP_IGNORED_LOCAL_GROUPS)
                    else:
                        grps = Group.objects.all()
                    for grp in grps:
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

                                logger.info("AUDIT LOGIN FOR: %s AT %s DETECTED IN GROUP %s" %
                                            (username, datetime.now(), resp['dn']))
                                # special super user group
                                if alter_superuser_membership:
                                    if resp['dn'] in settings.LDAP_SUPERUSER_GROUPS:
                                        usr.is_superuser = True
                                        logger.info("AUDIT LOGIN FOR: %s AT %s GRANTING ADMIN RIGHTS" %
                                                    (username, datetime.now()))
                                    else:
                                        logger.info("AUDIT LOGIN FOR: %s AT %s DENY ADMIN RIGHTS" %
                                                    (username, datetime.now()))
                                # special staff group
                                if alter_staff_membership:
                                    if resp['dn'] in settings.LDAP_STAFF_GROUPS:
                                        usr.is_staff = True
                                        logger.info("AUDIT LOGIN FOR: %s AT %s GRANTING STAFF RIGHTS" %
                                                    (username, datetime.now()))
                                    else:
                                        logger.info("AUDIT LOGIN FOR: %s AT %s DENY STAFF RIGHTS" %
                                                    (username, datetime.now()))
                                # other groups membership
                                for grp in settings.LDAP_GROUPS_MAP.keys():
                                    if resp['dn'] == settings.LDAP_GROUPS_MAP[grp]:
                                        try:
                                            logger.info(grp)
                                            usr.groups.add(Group.objects.get(name=grp))
                                            logger.info("AUDIT LOGIN FOR: %s AT %s ADDING GROUP %s MEMBERSHIP" %
                                                        (username, datetime.now(), grp))
                                        except ObjectDoesNotExist:
                                            pass
                    usr.save()

                con.unbind()

                # if set, apply min group membership
                logger.info("AUDIT LOGIN FOR: %s AT %s BEFORE MIN GROUP MEMBERSHIP" %
                            (username, datetime.now()))
                if hasattr(settings, 'LDAP_MIN_GROUPS'):
                    for grp in settings.LDAP_MIN_GROUPS:
                        logger.info("AUDIT LOGIN FOR: %s AT %s MIN GROUP MEMBERSHIP: %s" %
                                    (username, datetime.now(), grp))
                        try:
                            usr.groups.add(Group.objects.get(name=grp))
                            logger.info("AUDIT LOGIN FOR: %s AT %s ADDING GROUP %s MIN MEMBERSHIP" %
                                        (username, datetime.now(), grp))
                        except ObjectDoesNotExist:
                            pass

                # if you want to be able to get full user DN from session, store it
                if hasattr(settings, 'LDAP_STORE_USER_DN') \
                        and isinstance(settings.LDAP_USE_LDAP_GROUPS, bool) \
                        and settings.LDAP_USE_LDAP_GROUPS:
                    usr.dn = user_dn

                # if you want to know in which business unit the user is, check it
                if hasattr(settings, 'LDAP_STORE_BUSINESS_UNIT') \
                        and isinstance(settings.LDAP_STORE_BUSINESS_UNIT, dict):
                    user_bu = ','.join(user_dn.split(',')[1:])

                    if user_bu in settings.LDAP_STORE_BUSINESS_UNIT:
                        usr.bu = settings.LDAP_STORE_BUSINESS_UNIT[user_bu]

                return usr
        return None

    def get_user(self, user_id):
        user_model = get_user_model()
        try:
            return user_model.objects.get(pk=user_id)
        except user_model.DoesNotExist:
            return None

    """
    After many and many tries, it seems that, even if I use the default users and groups objects, Django does not
    give the good permission to non admin users.
    That's why there is now a minimalistic has_perm method.
    """

    def has_perm(self, user, perm, obj=None):
        mod, code = perm.split('.')
        for perm in user.user_permissions.all():
            if perm.codename == code and perm.content_type.app_label == mod:
                return True

        for grp in user.groups.all():
            for perm in grp.permissions.all():
                if perm.codename == code and perm.content_type.app_label == mod:
                    return True
        return False

    """
    Update user's attributes in DB from LDAP attributes
    """

    def update_user(self, user, attributes):
        if user is not None:
            for attr in settings.LDAP_ATTRIBUTES_MAP.keys():
                if settings.LDAP_ATTRIBUTES_MAP[attr] in attributes \
                        and len(attributes[settings.LDAP_ATTRIBUTES_MAP[attr]]) >= 1 \
                        and hasattr(user, attr):
                    if isinstance(attributes[settings.LDAP_ATTRIBUTES_MAP[attr]], string_types):
                        attribute_value = attributes[settings.LDAP_ATTRIBUTES_MAP[attr]]
                    else:
                        attribute_value = attributes[settings.LDAP_ATTRIBUTES_MAP[attr]][0]
                    setattr(user, attr, attribute_value)
        user.save()
