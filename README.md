# Simple LDAP/AD auth for django

considering that I did not find any working auth module for django able to work with MS Active Directory as a LDAP Server,
I started to build my own.

## LDAP CONFIG
### servers

    LDAP_SERVERS = [
        {
            'host': '<server 1 IP>',
            'port': 389,
            'use_ssl': False,
        },
        {
            'host': '<server 2 IP>',
            'port': 389,
            'use_ssl': False,
        },
    ]

### user and password to be able to bind and search for users and groups

    LDAP_BIND_USER = "cn=xxx,dc=domain,dc=local"
    LDAP_BIND_PWD = "pass"

### search parameters

    LDAP_SEARCH_BASE = "dc=domain,dc=local"
    LDAP_USER_SEARCH_FILTER = "(&(sAMAccountName=%s)(objectClass=user))"
    LDAP_GROUPS_SEARCH_FILTER = "(&(objectClass=group))"
    LDAP_GROUP_MEMBER_ATTRIBUTE = "member"

### attributes mapping

    LDAP_ATTRIBUTES_MAP = {
        'username': 'sAMAccountName',
        'first_name': 'givenName',
        'last_name': 'sn',
        'email': 'mail',
    }

### groups mapping to django's groups

    LDAP_SUPERUSER_GROUPS = ["CN=admin,dc=domain,dc=local", ]
    LDAP_STAFF_GROUPS = ["CN=staff,dc=domain,dc=local", ]
    LDAP_GROUPS_MAP = {
        'Compta': "cn=mygrp,dc=domain,dc=local",
    }

### Auth backend setting

    AUTHENTICATION_BACKENDS = ("django_auth_ldap3_ad.auth.LDAP3ADBackend",)
