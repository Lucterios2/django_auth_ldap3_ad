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
import ssl
from six import string_types
import logging

from ldap3 import Tls, Server, ServerPool, Connection
from ldap3 import MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, MODIFY_INCREMENT
from ldap3 import FIRST, SIMPLE

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save
from django.contrib.auth.signals import user_logged_in

logger = logging.getLogger(__name__)


def get_server_pool():
    if hasattr(settings, 'LDAP_CERT_FILE'):
        tls = Tls(validate=ssl.CERT_OPTIONAL, version=ssl.PROTOCOL_TLSv1, ca_certs_file=settings.LDAP_CERT_FILE)
    else:
        tls = None
    pool = ServerPool(None, pool_strategy=FIRST, active=True)
    for srv in settings.LDAP_SERVERS:
        # from rechie, pullrequest #30
        # check if LDAP_SERVERS settings has set ldap3 `get_info` parameter
        if 'get_info' in srv:
            server = Server(srv['host'], srv['port'], srv['use_ssl'], get_info=srv['get_info'], tls=tls)
        else:
            server = Server(srv['host'], srv['port'], srv['use_ssl'])
        pool.add(server)
    return pool


class NoneUser(object):

    @classmethod
    def can_used(cls):
        return False

    def connect(self):
        return

    def get_user_dn(self, username):
        return None, {}

    def create_record(self, user_dn, **user_attribs):
        return

    def update_record(self, user_dn, action=MODIFY_REPLACE, **attributes):
        return

    @staticmethod
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

    @classmethod
    def connect_to_signals(cls):
        user_logged_in.connect(NoneUser.user_logged_in_handler)


class AbstractUser(NoneUser):

    @classmethod
    def can_used(cls):
        return (getattr(settings, 'LDAP_WRITTEN_BY_DJANGO', False) is True) and hasattr(settings, 'LDAP_SERVERS') and hasattr(settings, 'LDAP_BIND_ADMIN') and hasattr(settings, 'LDAP_BIND_ADMIN_PASS')

    @classmethod
    def factory(cls):
        for sub_cls in cls.__subclasses__():
            if sub_cls.can_used():
                return sub_cls()
        return NoneUser()

    def __init__(self):
        self.pool = None
        self.con = None

    def __enter__(self):
        if self.con is None:
            self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.con is not None:
            self.con.unbind()

    def connect(self):
        # check configuration
        if not self.can_used():
            raise ImproperlyConfigured()
        if self.pool is None:
            self.pool = get_server_pool()
        # then, try to connect with user/pass from settings
        self.con = Connection(self.pool, auto_bind=True, authentication=SIMPLE,
                              user=settings.LDAP_BIND_ADMIN, password=settings.LDAP_BIND_ADMIN_PASS)

    def get_user_dn(self, username):
        if not (hasattr(settings, 'LDAP_SEARCH_BASE') and hasattr(settings, 'LDAP_USER_SEARCH_FILTER') and hasattr(settings, 'LDAP_ATTRIBUTES_MAP')):
            raise ImproperlyConfigured()
        self.con.search(settings.LDAP_SEARCH_BASE, settings.LDAP_USER_SEARCH_FILTER.replace('%s', '{0}').format(username),
                        attributes=list(settings.LDAP_ATTRIBUTES_MAP.values()))
        if self.con.result['result'] == 0 and len(self.con.response) > 0 and 'dn' in self.con.response[0].keys():
            user_dn = self.con.response[0]['dn']
            attributs = self.con.response[0]['attributes']
            fields = {}
            for attr in settings.LDAP_ATTRIBUTES_MAP.keys():
                if settings.LDAP_ATTRIBUTES_MAP[attr] in attributs \
                        and (len(attributs[settings.LDAP_ATTRIBUTES_MAP[attr]]) >= 1):
                    if isinstance(attributs[settings.LDAP_ATTRIBUTES_MAP[attr]], string_types):
                        attribute_value = attributs[settings.LDAP_ATTRIBUTES_MAP[attr]]
                    else:
                        attribute_value = attributs[settings.LDAP_ATTRIBUTES_MAP[attr]][0]
                    fields[attr] = attribute_value
            return user_dn, fields
        else:
            return None, {}

    def create_record(self, user_dn, **user_attribs):
        if self.con is None:
            self.connect()
        attribs_null = [attrib[0] for attrib in user_attribs.items() if attrib[1] is None]
        for attribs in attribs_null:
            user_attribs.pop(attribs)
        if hasattr(settings, "LDAP_ATTRIBUTES_MAP") and isinstance(settings.LDAP_ATTRIBUTES_MAP, dict):
            forbidden_attrib = []
            for attrib in settings.LDAP_ATTRIBUTES_MAP.values():
                if attrib not in user_attribs:
                    forbidden_attrib.append(attrib)
            if len(forbidden_attrib) > 0:
                raise ImproperlyConfigured("Forbidden attrib : %s" % forbidden_attrib)
        logger.debug(" > create_record %s = %s" % (user_dn, self.con.add(user_dn, attributes=user_attribs)))
        return self.con.result

    def update_record(self, user_dn, action=MODIFY_REPLACE, **attributes):
        if self.con is None:
            self.connect()

        if len(attributes) == 0:
            return

        if action not in [MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT]:
            raise ImproperlyConfigured()

        attribs = {}
        for attr in attributes.keys():
            attribs[attr] = [(action, [attributes[attr]])]

        self.con.modify(user_dn, attribs)
        return self.con.result

    def update_password(self, user_dn, newpassword):
        self.update_record(user_dn, userPassword=newpassword)

    @classmethod
    def before_save_user(cls, sender, instance, **kwargs):
        if not hasattr(instance, "_ldapauth"):
            try:
                with cls() as ad_ldap_user:
                    CurrentUser = get_user_model()
                    username_field = getattr(settings, 'LDAP_USER_MODEL_USERNAME_FIELD', 'username')
                    if instance.pk is not None:
                        try:
                            old_instance = CurrentUser._default_manager.get(pk=instance.pk)
                        except ObjectDoesNotExist:
                            old_instance = instance
                    else:
                        old_instance = instance
                    instance._ldap_dn, instance._ldap_fields = ad_ldap_user.get_user_dn(getattr(old_instance, username_field))
                    instance._ldap_password = instance._password
                    if instance._ldap_dn is not None:
                        suffix = getattr(settings, 'LDAP_WRITTEN_BY_DJANGO_USER_SUFFIX', '')
                        if (len(suffix) > 0) and not suffix[0].isalpha() and (suffix[0] in instance.username) and (len(instance.username.split(suffix[0])[-1]) > 0):
                            suffix = suffix[0] + instance.username.split(suffix[0])[-1]
                            instance.username = instance.username[:-1 * len(suffix)]
                        elif not instance.username.endswith(suffix):
                            instance.username = instance.username[:-1 * len(suffix)]
                        instance.username = instance._ldap_fields['username']
                        username_suffix = ''
                        while (CurrentUser._default_manager.filter(username="%s%s%s" % (instance.username, username_suffix, suffix)).exclude(pk=instance.pk).count() > 0):
                            if username_suffix == '':
                                username_suffix = 0
                            username_suffix += 1
                        instance.username += str(username_suffix) + suffix
                        logger.debug("**** before_save_user(%s) -> %s" % (instance.username, instance._ldap_dn))
            except AttributeError as err:
                logger.exception("**** before_save_user(%s) - error = %s" % (instance.username, err))

    @classmethod
    def disabled_user(cls, instance):
        cls._disconnect_to_signals()
        try:
            instance.is_active = False
            instance.save()
        finally:
            cls._connect_to_signals()
        return

    @staticmethod
    def get_user_search_group():
        MEMBEROF = 'memberof'
        settings.LDAP_USER_SEARCH_FILTER
        pos_begin = settings.LDAP_USER_SEARCH_FILTER.find(MEMBEROF)
        pos_end = settings.LDAP_USER_SEARCH_FILTER.find(')', pos_begin)
        if (pos_begin != -1) and (pos_end != -1):
            return settings.LDAP_USER_SEARCH_FILTER[pos_begin + len(MEMBEROF) + 1:pos_end]
        else:
            return None

    @classmethod
    def after_save_user(cls, sender, instance, **kwargs):
        if hasattr(instance, "_ldap_dn") and hasattr(instance, "_ldap_fields"):
            with cls() as ad_ldap_user:
                try:
                    attributes = {}
                    for fieldname, attrib in settings.LDAP_ATTRIBUTES_MAP.items():
                        if (fieldname not in instance._ldap_fields) or (getattr(instance, fieldname) != instance._ldap_fields[fieldname]):
                            attributes[attrib] = getattr(instance, fieldname)
                            if (getattr(settings, 'LDAP_USER_MODEL_USERNAME_FIELD', 'username') == fieldname) and (attributes[attrib] in ('', None)):
                                cls.disabled_user(instance)
                                logger.warning(" > User %s has not field %s" % (instance.username, fieldname))
                                return
                    if instance._ldap_dn is None:
                        ldap_map = getattr(settings, 'LDAP_ATTRIBUTES_MAP', {})
                        ldapident = ldap_map['username'] if 'username' in ldap_map else 'uid'
                        instance._ldap_dn = "%s=%s,%s" % (ldapident, attributes[ldapident], settings.LDAP_SEARCH_BASE)
                        if not ad_ldap_user.create_record(instance._ldap_dn, **attributes):
                            cls.disabled_user(instance)
                            logger.warning(" > User %s not create in directory : disabled " % (instance.username, ))
                            return
                        logger.info(" > User %s created " % (instance.username, ))
                    else:
                        ad_ldap_user.update_record(instance._ldap_dn, **attributes)
                    if instance._ldap_password is not None:
                        ad_ldap_user.update_password(instance._ldap_dn, instance._ldap_password)
                    user_group_dn = cls.get_user_search_group()
                    if user_group_dn is not None:
                        ad_ldap_user.update_record(user_group_dn, action=MODIFY_ADD, member=instance._ldap_dn)
                    if getattr(settings, 'LDAP_USE_LDAP_GROUPS', False) is True:
                        superuser_groups_dn = getattr(settings, 'LDAP_SUPERUSER_GROUPS', [])
                        if len(superuser_groups_dn) > 0:
                            ad_ldap_user.update_record(superuser_groups_dn[0], action=MODIFY_ADD if instance.is_superuser else MODIFY_DELETE, member=instance._ldap_dn)
                        staff_groups_dn = getattr(settings, 'LDAP_STAFF_GROUPS', [])
                        if len(staff_groups_dn) > 0:
                            ad_ldap_user.update_record(staff_groups_dn[0], action=MODIFY_ADD if instance.is_staff else MODIFY_DELETE, member=instance._ldap_dn)
                        group_list = [grp.name for grp in instance.groups.all()]
                        for group_name, group_dn in getattr(settings, 'LDAP_GROUPS_MAP', {}).items():
                            if group_name in group_list:
                                ad_ldap_user.update_record(group_dn, action=MODIFY_ADD, member=instance._ldap_dn)
                            else:
                                ad_ldap_user.update_record(group_dn, action=MODIFY_DELETE, member=instance._ldap_dn)
                    logger.debug("**** after_save_user(%s) -> %s = %s" % (instance.username, instance._ldap_dn, attributes))
                except Exception:
                    logger.exception("**** after_save_user(%s)" % instance.username)

    @classmethod
    def connect_to_signals(cls):
        super(AbstractUser, cls).connect_to_signals()
        if cls.can_used():
            cls._connect_to_signals()
            logger.debug("**** %s.connect_to_signals()" % cls.__name__)

    @classmethod
    def _connect_to_signals(cls):
        CurrentUser = get_user_model()
        pre_save.connect(cls.before_save_user, sender=CurrentUser)
        post_save.connect(cls.after_save_user, sender=CurrentUser)

    @classmethod
    def _disconnect_to_signals(cls):
        CurrentUser = get_user_model()
        pre_save.disconnect(cls.before_save_user, sender=CurrentUser)
        post_save.disconnect(cls.after_save_user, sender=CurrentUser)
