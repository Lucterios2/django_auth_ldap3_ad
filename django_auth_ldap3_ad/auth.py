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
import logging
from six import string_types
from ldap3 import Connection, SYNC, SIMPLE

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import ObjectDoesNotExist, ImproperlyConfigured
from django.utils import timezone
from django.contrib.auth.backends import ModelBackend

from django_auth_ldap3_ad.abstract_users import AbstractUser, get_server_pool

logger = logging.getLogger(__name__)


AbstractUser.factory().connect_to_signals()


def create_password():
    # generate password
    chars = string.ascii_letters + string.digits + '!@#$%&*'
    random.seed = (os.urandom(1024))
    families = 0
    passwd = ''
    while families < 3:
        passwd = ''.join(random.choice(chars) for _ in range(10))
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


class NoPermissionError(Exception):
    pass


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

    def __init__(self):
        self.username = None
        self.user_dn = None
        self.user = None
        self.attributs = None
        self.ldap_engine = 'AD'  # to keep compatibility with previous version
        self.group_search_filter = ''

    def check_configuration(self):
        # add LDAP_BIND_PASSWORD as password field
        password_field = 'LDAP_BIND_PWD' if hasattr(settings, 'LDAP_BIND_PWD') else 'LDAP_BIND_PASSWORD'

        # check configuration
        if not (hasattr(settings, 'LDAP_SERVERS') and hasattr(settings, 'LDAP_BIND_USER') and hasattr(settings, password_field) and hasattr(settings, 'LDAP_SEARCH_BASE') and
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
        if (hasattr(settings, 'LDAP_IGNORED_LOCAL_GROUPS') and not isinstance(settings.LDAP_IGNORED_LOCAL_GROUPS, list)):
            raise ImproperlyConfigured()

        if hasattr(settings, 'LDAP_AUTHENTICATION'):
            authentication = getattr(settings, 'LDAP_AUTHENTICATION')
        else:
            authentication = SIMPLE

        return password_field, authentication

    def init_and_get_ldap_user(self):
        # search capacities differs on LDAP engines.
        if hasattr(settings, 'LDAP_ENGINE') and settings.LDAP_ENGINE is not None:
            self.ldap_engine = settings.LDAP_ENGINE

        password_field, authentication = self.check_configuration()
        if LDAP3ADBackend.pool is None:
            LDAP3ADBackend.pool = get_server_pool()

        self.user_dn = None
        self.attributs = None
        # then, try to connect with user/pass from settings
        with Connection(LDAP3ADBackend.pool, auto_bind=True, client_strategy=SYNC, user=settings.LDAP_BIND_USER,
                        password=getattr(settings, password_field) or settings.LDAP_BIND_PASSWORD,
                        authentication=authentication, check_names=True) as con:
            # search for the desired user
            attributes = list(settings.LDAP_ATTRIBUTES_MAP.values())
            attributes.append('userPassword')
            con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_USER_SEARCH_FILTER.replace('%s', '{0}').format(self.username),
                       attributes=attributes)
            if con.result['result'] == 0 and len(con.response) > 0 and 'dn' in con.response[0].keys():
                self.user_dn = con.response[0]['dn']
                self.attributs = con.response[0]['attributes']
                # from rechie, pullrequest #30
                # convert `attributs` values to string if the returned value is a list
                for attrib in self.attributs:
                    if isinstance(self.attributs[attrib], list) and self.attributs[attrib]:
                        self.attributs[attrib] = self.attributs[attrib][0]
                    else:
                        self.attributs[attrib] = None

    """
    Authentication method for Django against AD/LDAP
    First, retrieve the user's DN based on it's username
    then, try to authenticate against the LDAP server pool using the DN and password.
    If ok, update user's attributes with LDAP ones and, if configured, update the group list.
    Finally, if setup, adds the minimal group membership common to all users
    """

    def set_groups_search_filter_AD(self):
        # inspired from
        # https://github.com/Lucterios2/django_auth_ldap3_ad/commit/ce24d4687f85ed12a0c4c796022ae7dcb3ff38e3
        # by jobec
        self.group_search_filter = settings.LDAP_GROUPS_SEARCH_FILTER
        all_ldap_groups = []
        for group in settings.LDAP_SUPERUSER_GROUPS + settings.LDAP_STAFF_GROUPS + list(settings.LDAP_GROUPS_MAP.values()):
            all_ldap_groups.append("(distinguishedName={0})".format(group))

        if len(all_ldap_groups) > 0:
            self.group_search_filter = "(&{0}(|{1}))".format(settings.LDAP_GROUPS_SEARCH_FILTER,
                                                             "".join(all_ldap_groups))

    def set_groups_search_filter_OpenLDAP(self):
        # add filter on member
        self.group_search_filter = "(&%s(member=%s))" % (settings.LDAP_GROUPS_SEARCH_FILTER, self.user_dn)
        # add filter on groups to match
        all_ldap_groups = []
        for group in settings.LDAP_SUPERUSER_GROUPS + settings.LDAP_STAFF_GROUPS + list(settings.LDAP_GROUPS_MAP.values()):
            if "(%s)" % group.split(',')[0] not in all_ldap_groups:
                all_ldap_groups.append("(%s)" % group.split(',')[0])

        if len(all_ldap_groups) > 0:
            self.group_search_filter = "(&{0}(|{1}))".format(self.group_search_filter, "".join(all_ldap_groups))

    def _return_user(self):
        """
        We add special attributes only during the authentication process to store user DN & Business Unit
        Those attributes are saved in the current session by the user_logged_in_handler
        """
        user_model = get_user_model()
        user_model.dn = lambda: None
        user_model.bu = lambda: None
        try:
            username_field = getattr(settings, 'LDAP_USER_MODEL_USERNAME_FIELD', 'username')
            lookup_username = self.attributs[settings.LDAP_ATTRIBUTES_MAP[username_field]]
            self.user = user_model.objects.filter(**{
                "{0}__iexact".format(username_field): lookup_username
            }).order_by('-last_login').first()
            if (self.user is not None) and (self.user.is_active is False):
                self.user = None
                raise NoPermissionError("user not active")
            if self.user is None:
                self.user = user_model()
        except user_model.DoesNotExist:
            # user does not exist in database already, create it
            self.user = user_model()
        self.user._ldapauth = True  # internal field to know that this user is manage by auth

    def _check_internal_password(self, password):
        if AbstractUser.factory().can_used():
            self._return_user()
            try:
                if (self.user.id is not None) and self.user.check_password(password):
                    with AbstractUser.factory() as ldap_user:
                        ldap_user.update_password(self.user_dn, password)
                        logger.debug(" > change of internal password from %s" % (self.user_dn, ))
                else:
                    logger.debug(" > bad internal password from %s" % (self.user_dn, ))
            finally:
                self.user = None

    def _update_user(self, password):
        """
        Update user's attributes in DB from LDAP attributes
        """
        if self.user is not None:
            for attr in settings.LDAP_ATTRIBUTES_MAP.keys():
                if settings.LDAP_ATTRIBUTES_MAP[attr] in self.attributs \
                        and len(self.attributs[settings.LDAP_ATTRIBUTES_MAP[attr]]) >= 1 \
                        and hasattr(self.user, attr):
                    if isinstance(self.attributs[settings.LDAP_ATTRIBUTES_MAP[attr]], string_types):
                        attribute_value = self.attributs[settings.LDAP_ATTRIBUTES_MAP[attr]]
                    else:
                        attribute_value = self.attributs[settings.LDAP_ATTRIBUTES_MAP[attr]][0]
                    setattr(self.user, attr, attribute_value)
        if hasattr(settings, 'LDAP_OBFUSCATE_PASS') and settings.LDAP_OBFUSCATE_PASS:
            self.user.set_password(create_password())
        else:
            self.user.set_password(password)
        self.user.last_login = timezone.now()
        self.user.save()

    def _clean_old_group_membership(self):
        logger.debug("AUDIT LOGIN FOR: %s CLEANING OLD GROUP MEMBERSHIP" % (self.username, ))
        if hasattr(settings, 'LDAP_IGNORED_LOCAL_GROUPS'):
            grps = Group.objects.exclude(name__in=settings.LDAP_IGNORED_LOCAL_GROUPS)
        else:
            grps = Group.objects.all()
        for grp in grps:
            grp.user_set.remove(self.user)
            grp.save()

    def _assign_group_superuser_staff(self, connection_ldap):
        # check for groups membership
        # first cleanup
        alter_superuser_membership = False
        if hasattr(settings, 'LDAP_SUPERUSER_GROUPS') and isinstance(settings.LDAP_SUPERUSER_GROUPS, list) and len(settings.LDAP_SUPERUSER_GROUPS) > 0:
            self.user.is_superuser = False
            alter_superuser_membership = True
        alter_staff_membership = False
        if hasattr(settings, 'LDAP_STAFF_GROUPS') and isinstance(settings.LDAP_STAFF_GROUPS, list) and len(settings.LDAP_STAFF_GROUPS) > 0:
            self.user.is_staff = False
            alter_staff_membership = True
        # then re-fill
        connection_ldap.search(settings.LDAP_GROUPS_SEARCH_BASE if hasattr(settings, 'LDAP_GROUPS_SEARCH_BASE') else settings.LDAP_SEARCH_BASE,
                               self.group_search_filter, attributes=['cn', settings.LDAP_GROUP_MEMBER_ATTRIBUTE])
        if len(connection_ldap.response) > 0:
            for resp in connection_ldap.response:
                if 'attributes' in resp and settings.LDAP_GROUP_MEMBER_ATTRIBUTE in resp['attributes'] \
                        and self.user_dn in resp['attributes'][settings.LDAP_GROUP_MEMBER_ATTRIBUTE]:

                    logger.debug("AUDIT LOGIN FOR: %s DETECTED IN GROUP %s" %
                                 (self.username, resp['dn']))
                    # special super user group
                    if alter_superuser_membership:
                        if resp['dn'] in settings.LDAP_SUPERUSER_GROUPS:
                            self.user.is_superuser = True
                            logger.debug("AUDIT LOGIN FOR: %s GRANTING ADMIN RIGHTS" %
                                         (self.username,))
                        else:
                            logger.debug("AUDIT LOGIN FOR: %s DENY ADMIN RIGHTS" %
                                         (self.username,))
                    # special staff group
                    if alter_staff_membership:
                        if resp['dn'] in settings.LDAP_STAFF_GROUPS:
                            self.user.is_staff = True
                            logger.debug("AUDIT LOGIN FOR: %s GRANTING STAFF RIGHTS" %
                                         (self.username,))
                        else:
                            logger.debug("AUDIT LOGIN FOR: %s DENY STAFF RIGHTS" %
                                         (self.username,))
                    # other groups membership
                    for grp in settings.LDAP_GROUPS_MAP.keys():
                        if resp['dn'] == settings.LDAP_GROUPS_MAP[grp]:
                            try:
                                logger.debug(grp)
                                self.user.groups.add(Group.objects.get(name=grp))
                                logger.debug("AUDIT LOGIN FOR: %s ADDING GROUP %s MEMBERSHIP" %
                                             (self.username, grp))
                            except ObjectDoesNotExist:
                                pass

    def _assign_mingroup_sessioninfo(self):
        # if set, apply min group membership
        logger.debug("AUDIT LOGIN FOR: %s BEFORE MIN GROUP MEMBERSHIP" % (self.username, ))
        if hasattr(settings, 'LDAP_MIN_GROUPS'):
            for grp in settings.LDAP_MIN_GROUPS:
                logger.debug(
                    "AUDIT LOGIN FOR: %s MIN GROUP MEMBERSHIP: %s" % (self.username, grp))
                try:
                    self.user.groups.add(Group.objects.get(name=grp))
                    logger.debug(
                        "AUDIT LOGIN FOR: %s ADDING GROUP %s MIN MEMBERSHIP" % (self.username, grp))
                except ObjectDoesNotExist:
                    pass
        # if you want to be able to get full user DN from session, store it
        if hasattr(settings, 'LDAP_STORE_USER_DN') and isinstance(settings.LDAP_USE_LDAP_GROUPS, bool) and settings.LDAP_USE_LDAP_GROUPS:
            self.usr.dn = self.user_dn
        # if you want to know in which business unit the user is, check it
        if hasattr(settings, 'LDAP_STORE_BUSINESS_UNIT') and isinstance(settings.LDAP_STORE_BUSINESS_UNIT, dict):
            user_bu = ','.join(self.user_dn.split(',')[1:])
            if user_bu in settings.LDAP_STORE_BUSINESS_UNIT:
                self.user.bu = settings.LDAP_STORE_BUSINESS_UNIT[user_bu]

    def authenticate(self, request, username=None, password=None):
        logger.debug("AUDIT BEGIN LOGIN PROCESS FOR: %s" % (username,))
        if username is None or username == '':
            return None
        self.username = username

        self.init_and_get_ldap_user()
        if self.user_dn is not None and self.attributs is not None:
            # now, we know the dn of the user, we try a simple bind. This way,
            # the LDAP checks the password with it's algorithm and the active state of the user in one test
            if self.attributs['userPassword'] is None:
                self._check_internal_password(password)
            con = Connection(LDAP3ADBackend.pool, user=self.user_dn, password=password)
            if con.bind():
                try:
                    logger.info("AUDIT SUCCESS LOGIN FOR: %s" % (self.username,))

                    self._return_user()
                    # update existing or new user with LDAP data
                    self._update_user(password)

                    # if we want to use LDAP group membership:
                    if LDAP3ADBackend.use_groups:
                        # if using AD filter groups in result by using groups in the config
                        if self.ldap_engine == 'AD':
                            self.set_groups_search_filter_AD()
                        # if using OpenLDAP, filter groups in search by membership of the user
                        elif self.ldap_engine == 'OpenLDAP':
                            self.set_groups_search_filter_OpenLDAP()
                        logger.debug("AUDIT LOGIN FOR: %s USING LDAP GROUPS" % (username,))
                        if getattr(settings, 'LDAP_USE_LDAP_GROUPS_FOR_ADMIN_STAFF_ONLY', False) is False:
                            self._clean_old_group_membership()
                        self._assign_group_superuser_staff(con)
                        self.user.save()
                except NoPermissionError:
                    return None
                finally:
                    con.unbind()
                self._assign_mingroup_sessioninfo()
            return self.user
        return None

    def user_can_authenticate(self, user):
        if getattr(settings, 'LDAP_UNCHECK_USER_ACTIVE', True):
            return True
        else:
            return super(LDAP3ADBackend, self).user_can_authenticate(user)
