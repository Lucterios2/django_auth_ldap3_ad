# Simple LDAP/AD auth for django

considering that I did not find any working auth module for django able to work with MS Active Directory as a LDAP Server,
I started to build my own.

Once configured as described bellow, the module authenticates users against a single or a pool of LDAP servers and tries
reconciling the user with the local django database.
If user does not exists locally, it creates it, else it updates it.
Moreover, it tries to determine group membership following the rules given in settings.py

## LDAP CONFIG
### servers

Mandatory parameter.
List of LDAP server to authenticate against. 3 information are needed for each:
- it's name or IP (prefer IP to avoid spending time with the DNS lookup)
- the TCP port to connect on (default: 389 for non SSL and 636 for SSL)
- a boolean tag to enable or not the use of SSL during authentication process against this server.

You can define as many authentication servers as needed (as many as you have in you network) with, for each, it's own parameters.
The pool is used in the order you defined. If the first one is available, authentication is against it, if the server is not available, the next is used. In all cases, if an answer is received for a server, it's considered authoritative even if it's negative 

```python
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
```

### user and password to be able to bind and search for users and groups

Mandatory parameter.
To bind to a LDAP server, we need a fully qualified distinguished name. The user just needs minimal rights to walk through the directory. That's why it is recommended to create a dedicated user with no special rights and no groups to use here.

```python
LDAP_BIND_USER = "cn=xxx,dc=domain,dc=local"
LDAP_BIND_PWD = "pass"
```

### search parameters

Mandatory parameters.
Search parameters enables you to define a first level of filter for the users and groups taken into account.
Search base is used for every lookups so if you define it to the lower level, all users and groups of the directory are able to authenticate but if you define a subtree here, users and groups in other subtrees wont be able to do so.
Search filters for users and groups enables you to get a second level of filtering by forcing some additional conditions to be true for the object to be taken into account.
In LDAP, group membership is onwed by groups objects. Depending on the implementation (OpenLDAP, MS Active Directory, others), the attribute of group objects to inspect can differ. You need to determine the good attribute and name it in the LDAP_GROUP_MEMBER_ATTRIBUTE parameter for groups to be well used.

help for filters writing:

- [RedHat/CentOS CDS (based on OpenLDAP)](https://www.centos.org/docs/5/html/CDS/ag/8.0/Finding_Directory_Entries-LDAP_Search_Filters.html)
- [MS Active Directory](https://msdn.microsoft.com/en-us/library/aa746475%28v=vs.85%29.aspx)
- [ldapwiki (general LDAP purpose)](http://ldapwiki.willeke.com/wiki/LDAP)

```python
LDAP_SEARCH_BASE = "dc=domain,dc=local"
LDAP_USER_SEARCH_FILTER = "(&(sAMAccountName=%s)(objectClass=user))"
```

### attributes mapping

Mandatory parameter.
As the module uses django's user class to create a "replicate" of the LDAP user to the database, it needs to know which LDAP attribute to map with which django User's attribute (it depends on the implementation and you onw use of it).

```python
LDAP_ATTRIBUTES_MAP = {
    'username': 'sAMAccountName',
    'first_name': 'givenName',
    'last_name': 'sn',
    'email': 'mail',
}
```

### minimal group membership

If this parameter is set, the module takes care that each connected user is member of this groups whereas you want to use LDAP groups or not.

```python
LDAP_MIN_GROUPS = ["MyDjangoGroup", ]
```


### groups mapping to django's groups

First parameter of this group enables to use LDAP group binding or disable it to use local database groups only. A the first release of this module does have this parameter, for reverse compatibility, if this parameter does not exists, it is considered true. If it is configured to false, other parameters of this group wont be used nor checked.
If LDAP_GROUPS_SEARCH_BASE is not defined LDAP_SEARCH_BASE will be used as base for group lookup.
As django defines 2 special rights outside of the use of groups, the module can bind specific group membership to those 2 special attributes in addition to classical groups binding.
If superuser and staff parameters are not present, not a list or an empty list, those parameters are skipped. This way, you can use LDAP groups for "classical groups" and define manually in the database who will be superuser or staff user.

```python
LDAP_USE_LDAP_GROUPS = True
LDAP_GROUPS_SEARCH_BASE = "dc=domain,dc=local"
LDAP_GROUPS_SEARCH_FILTER = "(&(objectClass=group))"
LDAP_GROUP_MEMBER_ATTRIBUTE = "member"
LDAP_SUPERUSER_GROUPS = ["CN=admin,dc=domain,dc=local", ]
LDAP_STAFF_GROUPS = ["CN=staff,dc=domain,dc=local", ]
LDAP_GROUPS_MAP = {
    'my django group': "cn=my ldap group,dc=domain,dc=local",
}
```

### Auth backend setting

Mandatory parameter to tell django to use this module as it's authentication backend. See django's documentation to use it in an authentication chain. The example shows how to set it as the only authoritative authentication backend.

```python
AUTHENTICATION_BACKENDS = ("django_auth_ldap3_ad.auth.LDAP3ADBackend",)
```
