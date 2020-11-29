'''
# Copyright 2020 Netskope, Inc.
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
# disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
# products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Written by Colin Estep
'''

'''
This module is used represent entities in a GCP environment.
'''

import shlex
import subprocess
import sys
import re
import json
import logging

def load_bindings(obj):
    '''
    Loads the IAM bindings for a given object.
    '''
    logging.info("Getting bindings for " + obj.name)
    if isinstance(obj, Organization):
        my_cmd = shlex.split("gcloud organizations get-iam-policy " + obj.id + " --format json")
    elif isinstance(obj, Folder):
        my_cmd = shlex.split("gcloud resource-manager folders get-iam-policy " + obj.id + " --format json")
    elif isinstance(obj, Project):
        my_cmd = shlex.split("gcloud projects get-iam-policy " + obj.id + " --format json")
    elif isinstance(obj, ServiceAccount):
        my_cmd = shlex.split("gcloud iam service-accounts get-iam-policy " + obj.email + " --format json")
    else:
        logging.error("{0} is not a valid object type to get IAM bindings.".format(obj))
        return
    try:
        results = subprocess.check_output(my_cmd)
    except:
        logging.error("Encountered an error when running {0}".format(my_cmd))
        return
    data = json.loads(results)
    if 'bindings' in data.keys():
        return data['bindings']

class Organization:
    def __init__(self, org_dict):
        self.name = org_dict['displayName']
        self.create_time = org_dict['creationTime']
        self.owner = org_dict['owner']['directoryCustomerId']
        self.state = org_dict['lifecycleState']
        self.folders = list()
        self.projects = list()
        self.id = self.__process_org_string__(org_dict['name'])
        self.bindings = load_bindings(self)

    def __process_org_string__(self, org_string):
        org_elements = org_string.split('/')
        return org_elements[1]

    def add_folder(self, new_folder):
        for folder in self.folders:
            if folder.id == new_folder.id:
                return
        self.folders.append(new_folder)
        
    def add_project(self, new_project):
        for project in self.projects:
            if project.id == new_project.id:
                return
        self.projects.append(new_project)

    def get_projects(self):
        return self.projects
        
    def get_folders(self):
        return self.folders

    def get_bindings(self):
        return self.bindings
        
    def __repr__(self):
        return self.name

class Folder:
    def __init__(self, folder_data):
        self.name = folder_data['displayName']
        self.state = folder_data['lifecycleState']
        self.create_time = folder_data['createTime']
        self.folders = list()
        self.projects = list()
        self.__process_folder_strings__(folder_data['name'], folder_data['parent'])
        self.bindings = load_bindings(self)
        
    def __process_folder_strings__(self, name_string, parent_string):
        name_elements = name_string.split('/')
        parent_elements = parent_string.split('/')
        self.id = name_elements[1]
        self.parent_type = parent_elements[0]
        self.parent_id = parent_elements[1]
        
    def get_bindings(self):
        return self.bindings

    def get_folders(self):
        return self.folders
    
    def get_projects(self):
        return self.projects
        
    def add_project(self, new_project):
        for project in self.projects:
            if project.id == new_project.id:
                return
        self.projects.append(new_project)
        
    def add_folder(self, new_folder):
        for folder in self.folders:
            if folder.id == new_folder.id:
                return
        self.folders.append(new_folder)

    def __repr__(self):
        return self.name
        
class Project:
    def __init__(self, project_dict):
        self.id = project_dict['projectId']
        self.number = project_dict['projectNumber']
        self.state = project_dict['lifecycleState']
        self.create_time = project_dict['createTime']
        self.name = project_dict['projectId']
        self.compute_enabled = False
        self.hasBuckets = False
        self.service_accounts = list()
        self.ancestors = list()
        self.labels = dict()
        if 'labels' in project_dict.keys():
            self.labels = project_dict['labels']
        self.bindings = load_bindings(self)
        self.__load_service_accounts__()
        
    def __load_service_accounts__(self):
        logging.info("Getting Service Accounts for Project " + self.id)
        my_cmd = shlex.split("gcloud iam service-accounts list --project " + self.id + " --format json")
        try:
            results = subprocess.check_output(my_cmd)
        except:
            logging.error("Encountered an error when running {0}".format(my_cmd))
            return
        sa_data = json.loads(results)
        for item in sa_data:
            self.service_accounts.append(ServiceAccount(item))

    def load_ancestors(self):
        logging.info("Getting Ancestors for Project " + self.id)
        my_cmd = shlex.split("gcloud projects get-ancestors " + self.id + " --format json")
        try:
            results = subprocess.check_output(my_cmd)
        except:
            logging.error("Encountered an error when running {0}".format(my_cmd))
            return
        return json.loads(results)

    def get_service_accounts(self):
        return self.service_accounts

    def get_bindings(self):
        return self.bindings
    
    def __repr__(self):
        return self.id

class ServiceAccount:
    def __init__(self, sa):
        self.email = sa['email']
        self.name = sa['name']
        self.project_id = sa['projectId']
        self.disabled = sa['disabled']
        if 'description' in sa.keys():
            self.description = sa['description']
        self.id = sa['uniqueId']
        self.bindings = load_bindings(self)
    
    def get_bindings(self):
        return self.bindings
        
    def is_enabled(self):
        return not self.disabled

    def __repr__(self):
        return self.email
            
class Role:
    def __init__(self, name):
        self.name = name
        self.admin = False
        self.type = 'Predefined'
        self.scope = None
        self.location = None
        self.oslogin = None
        self.permissions = None
        self.description = None
        self.stage = None
        if re.search('projects/' or 'organizations/', self.name):
            # This is a custom role
            self.type = 'Custom'
            pieces = self.name.split('/')
            if pieces[0] == 'projects':
                self.scope = 'project'
            elif pieces[0] == 'organizations':
                self.scope = 'organization'
            self.location = pieces[1]
            self.name = pieces[3]

    def __get_data__(self):
        if self.type == "Custom":
            logging.info("Getting custom role data for {0}".format(self.name))
            my_cmd = shlex.split("gcloud beta iam roles describe " + self.name + " --" + self.scope + " " + self.location + " --format json")
        else:
            my_cmd = shlex.split("gcloud beta iam roles describe " + self.name + " --format json")
        
        try:
            results = subprocess.check_output(my_cmd)
        except:
            logging.error("Encountered an error when running {0}".format(my_cmd))
            return
        role_data = json.loads(results)
        self.permissions = role_data['includedPermissions']
        self.description = role_data['description']
        self.stage = role_data['stage']
        
    def __check_iam_admin__(self, permission):
        if re.search('setIamPolicy', permission):
            self.admin = True
    
    def __check_oslogin__(self, permission):
        if re.search('osLogin', permission):
            self.oslogin = True
    
    def __evaluate_permissions__(self):
        for permission in self.permissions:
            self.__check_iam_admin__(permission)
            self.__check_oslogin__(permission)

    def is_admin(self):
        self.__get_data__()
        self.__evaluate_permissions__()
        return self.admin

    def has_oslogin(self):
        self.__get_data__()
        self.__evaluate_permissions__()
        return self.oslogin   

class Member:
    def __init__(self, member_type, name):
        self.type = member_type
        self.name = name
        self.is_external = False
        self.sa_scopes = list()
        self.direct_bindings = {
            'organization': dict(),
            'folder': dict(),
            'project': dict(),
            'service_account': dict()
        }
        self.indirect_bindings = dict()
        
    def add_direct_binding(self, scope, binding_name, role):
        if scope not in ['organization', 'folder', 'project', 'service_account']:
            logging.error("{0} is not a valid structure in GCP, exiting.".format(scope))
            sys.exit()
            
        # If the scope and role are already in the bindings for some reason, don't do anything.
        ###
        # Check if the name of the org, folder, etc. exists
        if binding_name not in self.direct_bindings[scope].keys():
            self.direct_bindings[scope][binding_name] = dict()
            self.direct_bindings[scope][binding_name] = []
        
        # If the scope exists, but doesn't have this role yet, just add the role
        if role not in self.direct_bindings[scope][binding_name]:
            self.direct_bindings[scope][binding_name].append(role)
    
    def __repr__(self):
        return self.name
        
    def __eq__(self, other): 
        if not isinstance(other, Member):
            return NotImplemented
        return self.type == other.type and self.name == other.name        

    def __parse_roles__(self, role_name, scope):
        if scope not in ['all', 'organization', 'folder', 'project', 'service_account']:
            logging.error("{0} is not a valid structure in GCP, exiting.".format(scope))
            sys.exit()
        if scope == 'all':
            scope = [ 'organization', 'folder', 'project', 'service_account' ]
        else:
            scope = [ scope ]
        for item in scope:
            for binding_name in self.direct_bindings[item].keys():
                for role in self.direct_bindings[item][binding_name]:
                    if re.search(role_name, role, re.IGNORECASE):
                        return {item: binding_name}
        return None
            
    def __load_sa_member_info__(self, scope='all'):
        for item in [ self.__parse_roles__('serviceAccountUser', scope), self.__parse_roles__('roles/owner', scope), self.__parse_roles__('roles/editor', scope), self.__parse_roles__('serviceAccountTokenCreator', scope), self.__parse_roles__('serviceAccountAdmin', scope), self.__parse_roles__('serviceAccountKeyAdmin', scope), self.__parse_roles__('workloadIdentityUser', scope) ]:
            if item is not None:
                if 'service_account' in item.keys():
                    pieces = item['service_account'].split("/")
                    item['service_account'] = pieces[-1]
                self.sa_scopes.append(item)
        
    def is_service_account_member(self, scope='all'):
        self.__load_sa_member_info__(scope)
        # Skip if the special service accounts used by Google
        if len(self.sa_scopes) > 0 and '@cloudservices.gserviceaccount.com' not in self.name:
            return True
        return False

    def is_admin(self, scope='all'):
        # Validate the scope input
        if scope not in ['all', 'organization', 'folder', 'project', 'service_account']:
            logging.error("{0} is not a valid structure in GCP, exiting.".format(scope))
            sys.exit()
        if scope == 'all':
            scope = [ 'organization', 'folder', 'project' ]
        else:
            scope = [ scope ]
        for scope in scope:
            for binding_name in self.direct_bindings[scope].keys():
                for role in self.direct_bindings[scope][binding_name]:
                    '''
                        This is looking for:
                        1. Roles with Admin in the name 
                        2. Primitive roles of Owner or Editor
                        3. Roles with risky permissions
                    '''
                    if self.__parse_roles__('admin', scope):
                        return True
                    elif re.match('roles/editor', role) or re.match('roles/owner', role):
                        return True
                    else:
                        role_object = Role(role)
                        if role_object.is_admin():
                            return True
        return False
    
    def get_direct_bindings(self):
        return self.direct_bindings
        
    def get_member_report(self):
        '''
        Prepare the full member dictionary for reporting.
        '''
        member_dict = {
         'member':
         {
             'name': self.name,
             'type': self.type,
             'external_member': self.is_external_member(),
             'service_account_access': self.is_service_account_member(),
             'admin_level_access': self.is_admin(),
             'direct_bindings': self.direct_bindings,
             'indirect_bindings': self.indirect_bindings
         }
        }
        return member_dict

    def set_indirect_bindings(self, service_account_bindings):
        self.indirect_bindings = service_account_bindings
        
    def get_indirect_bindings(self):
        return self.indirect_bindings
        
    def set_external_member(self, value):
        self.is_external = value
        
    def is_external_member(self):
        return self.is_external
