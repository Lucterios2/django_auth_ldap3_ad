# Simple LDAP/AD auth for django

considering that I did not find any working auth module for django able to work with MS Active Directory as a LDAP Server,
I started to build my own.

Once configured as described bellow, the module authenticates users against a single or a pool of LDAP servers and tries
reconciling the user with the local django database.
If user does not exists locally, it creates it, else it updates it.
Moreover, it tries to determine group membership following the rules given in settings.py

## INSTALLATION
```bash
pip install django-auth-ldap3-ad
```

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

### LDAP engine

As some capabilities differs between LDAP engines, you can define your engine to use specific features.

Actual used values are:
- AD (default)
- OpenLDAP

```python
LDAP_ENGINE = 'OpenLDAP'
```

### user and password to be able to bind and search for users and groups

Mandatory parameter.
To bind to a LDAP server, we need a fully qualified distinguished name. The user just needs minimal rights to walk through the directory. That's why it is recommended to create a dedicated user with no special rights and no groups to use here.

```python
LDAP_BIND_USER = "cn=xxx,dc=domain,dc=local"
LDAP_BIND_PASSWORD = "pass"
```

You can also use LDAP_BIND_PWD for the bind password. `LDAP_BIND_PASSWORD` will be replaced with '****' in debug views like `django_debug_toolbar` while `LDAP_BIND_PWD` will not.

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
All `%s` in `LDAP_USER_SEARCH_FILTER` are replaced with `{0}` and the username is injected with `string.format`
With this you can use the username more than once.
e.g.
```python
LDAP_USER_SEARCH_FILTER = "(&(|(userPrincipalName={0})(sAMAccountName={0}))(objectClass=user))"
```
will match the username in either `sAMAccountName` or `userPrincipalName` so that users can then login with username or email address.


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

### changing username field in user model

Which user model field should be used as user login. Default: `username`.

```python
LDAP_USER_MODEL_USERNAME_FIELD = 'email'
```

Make sure field is mapped to LDAP attribute in `LDAP_ATTRIBUTES_MAP`.

### minimal group membership

If this parameter is set, the module takes care that each connected user is member of this groups whereas you want to use LDAP groups or not.

```python
LDAP_MIN_GROUPS = ["MyDjangoGroup", ]
```

### kept users in local groups

If this parameter is set, the module will kept users in these locally-defined groups. Otherwise, every group membership is refreshed (removed and readded) when a user authenticates. 

```python
LDAP_IGNORED_LOCAL_GROUPS = ["MyLocalDjangoGroup", ]
```

### groups mapping to django's groups

First parameter of this group enables to use LDAP group binding or disable it to use local database groups only. A the first release of this module does have this parameter, for reverse compatibility, if this parameter does not exists, it is considered true. If it is configured to false, other parameters of this group wont be used nor checked.
If LDAP_GROUPS_SEARCH_BASE is not defined LDAP_SEARCH_BASE will be used as base for group lookup.
As django defines 2 special rights outside of the use of groups, the module can bind specific group membership to those 2 special attributes in addition to classical groups binding.
If superuser and staff parameters are not present, not a list or an empty list, those parameters are skipped. This way, you can use LDAP groups for "classical groups" and define manually in the database who will be superuser or staff user.
With the addition of LDAP engine, LDAP_GROUPS_SEARCH_FILTER can be automatically enriched in 2 different ways:

using LDAP_ENGINE = 'AD' or without specifying it:
Thanks to jobec, LDAP_GROUPS_SEARCH_FILTER is now automatically enriched by the list of superuser, staff and map groups to limit search to the strictly needed ones and avoid troubles with LDAP having more than 1000 groups.

using LDAP_ENGINE = 'OpenLDAP':
The filter is automatically enriched using the user's DN and getting only groups the user is member of and part of the superuser, staff and map groups list.

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

### Store user DN in session for future use

You can ask this backend to store the LDAP user DN in the current session to be able to use it in another app.

```python
LDAP_STORE_USER_DN = True
```

You will retrieve the value in the session this way:

```python
request.session['LDAP_USER_DN']
```

### Determine and store user business unit in session for future use

You can ask this backend to determine and store the business unit of the user in the current session to be able to use it in another app.
To do so, you need to set a dict in your settings to bind LDAP Organisational Unit to your own business unit codes

```python
LDAP_STORE_BUSINESS_UNIT = {
    'OU=myOU1,DC=mydom,DC=local' = 'myBU1',
    'OU=myOU2,DC=mydom,DC=local' = 'myBU2',
}
```

You will retrieve your BU code in the session this way:

```python
request.session['LDAP_USER_BU']
```

### Auth backend setting

Mandatory parameter to tell django to use this module as it's authentication backend. See django's documentation to use it in an authentication chain. The example shows how to set it as the only authoritative authentication backend.

```python
AUTHENTICATION_BACKENDS = ("django_auth_ldap3_ad.auth.LDAP3ADBackend",)
```

### NEW in 1.6 series:

This auth module now comes with helpers to create a user in the Active Directory, update the password of the user, update the attributes of a user.
Caution: those helpers, especially the create user one, are specific to MS Active Directory even if they use LDAP protocol.

As those helpers will make changes in the directory, you MUST configure almost one server to use SSL LDAP binding. Other servers in you configuration will be ignored automatically by those helpers.
You must also provide a user with needed rights to add or modify users in the needed OU:

```python
LDAP_BIND_ADMIN = "CN=my admin,OU=x,DC=mydom,DC=local"
LDAP_BIND_ADMIN_PASS = "MySuperFunPassword"
```

To be able to create the user principal name, you must also provide the local domain of the AD:

```python
LDAP_AD_DOMAIN = "mydom.local"
```

The last setting is the path to the AD root certificate to enforce encryption between client and server:

```python
LDAP_CERT_FILE = "/path/to/mycert.pem"
```

Once your configuration updated, you will be able to use the helpers:

```python
from django_auth_ldap3_ad.ad_users import Aduser

adu = Aduser()
adu.create_ad_user(user_dn, firstname, lastname, sAMAccountName, mail=email, description=description)
adu.update_password_ad_user(user_dn, password)
adu.update_ad_user(user_dn, {'ldapAttrib1': 'value1', 'ldapAttrib2': 'value2'})
adu.activate_ad_user(user_dn)
```
