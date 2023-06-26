# This file is part of Flask-Multipass-LDAP-MLZ.
# Copyright (C) 2023 MLZ
#
# Flask-Multipass-LDAP-MLZ free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.


from flask_multipass.providers.ldap import LDAPIdentityProvider, LDAPGroup
from flask_multipass.providers.ldap.util import ldap_context, to_unicode

from flask_multipass.providers.ldap.operations import (build_group_search_filter,
                                                        build_user_search_filter,
                                                       get_group_by_id, get_user_by_id,
                                                       )
from flask_multipass.data import AuthInfo, IdentityInfo

class MLZLDAPGroup(LDAPGroup):
    def get_members(self):
        with ldap_context(self.ldap_settings):
            _, group_data = get_group_by_id(self.name,
                                                   attributes=['memberUid','gidNumber'])
            user_filter= build_user_search_filter({'gidNumber':  group_data.get('gidNumber')}, exact=True)
            # get users main group
            for _, user_data in self.provider._search_users(user_filter):
                user_data = to_unicode(user_data)
                yield IdentityInfo(self.provider, identifier=user_data[self.ldap_settings['uid']][0], **user_data)
            # get further groups
            for uid in group_data.get('memberUid'):
                _, user_data = get_user_by_id(uid)
                user_data = to_unicode(user_data)
                if user_data:
                    yield IdentityInfo(
                        self.provider,
                        identifier=user_data[self.ldap_settings['uid']][0],
                        **user_data)

    def has_member(self, user_identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(user_identifier)
            if not user_dn:
                return False
            _, group_data = get_group_by_id(self.name, attributes=['memberUid','gidNumber'])

            if user_data.get('gidNumber') ==  group_data.get('gidNumber', Ellipsis):
                return True
            if user_data[self.ldap_settings['uid']] in group_data.get('memberUid',[]):
                return True
        return False


class MLZLDAPIdentityProvider(LDAPIdentityProvider):
    group_class = MLZLDAPGroup
