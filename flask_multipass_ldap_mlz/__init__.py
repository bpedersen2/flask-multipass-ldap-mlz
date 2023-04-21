# This file is part of Flask-Multipass-LDAP-MLZ.
# Copyright (C) 2023 MLZ
#
# Flask-Multipass-LDAP-MLZ free software; you can redistribute it
# and/or modify it under the terms of the Revised BSD License.


import re

from flask_multipass.providers.ldap import LDAPIdentityProvider, LDAPGroup, LDAPAuthProvider




class MLZLDAPGroup(LDAPGroup):
    def get_members(self):
	with ldap_context(self.ldap_settings):
           group_dn, group_data = get_group_by_id(self.name, attributes=['memberUid'])
	   for uid in group_data.get('memberUid'):
		 _ , user_data = get_user_by_id(uid)
                 user_data = to_unicode(user_data)
                 yield IdentityInfo(self.provider, identifier=user_data[self.ldap_settings['uid']][0], **user_data)

    def has_member(self,  user_identifier):
        with ldap_context(self.ldap_settings):
            user_dn, user_data = get_user_by_id(user_identifier)
            if not user_dn:
                return False
            group_filter = build_group_search_filter({'cn':self.name, 'memberUid': user_data[self.ldap_settings['uid']][0]})
	    groups = self.provider._search_groups(group_filter)
	    if not groups:
		return False
        return True	
          
           






class MLZLDAPIdentityProvider(LDAPIdentityProvider):
    group_class = MLZLDAPGroup


