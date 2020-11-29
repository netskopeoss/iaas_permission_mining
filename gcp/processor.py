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
This module populates the GCP objects.
'''
import sys
import shlex
import subprocess
import json
import logging
from gcp import Organization, Folder, Project, Member

def merge_dictionaries(dict1, dict2):
    new_dict = dict1.copy()
    new_dict.update(dict2)
    return new_dict

def merge_bindings(dict1, dict2):
    new_dict = merge_dictionaries(dict1, dict2)      
    for scope in [ 'organization', 'folder', 'project', 'service_account' ]:
        if len(dict1[scope]) > 0:
            for key, value in dict1[scope].items():
                if key in new_dict[scope].keys() and value not in new_dict[scope][key]:
                    # Solve the conflict
                    if isinstance(new_dict[scope][key], list):
                        if isinstance(value, list):
                            new_dict[scope][key] = new_dict[scope][key] + value
                        else:
                            new_dict[scope][key].append(value)
                    elif isinstance(value, list):
                            new_dict[scope][key] = value.append(new_dict[scope][key])
                    else:
                        new_dict[scope][key] = [ new_dict[scope][key], value ]
                else:
                    #Add the new value to the composite dict
                    new_dict[scope][key] = value
                # Make sure we only have unique roles, no duplicates
                my_set = set(new_dict[scope][key])
                new_dict[scope][key] = list(my_set)
    return new_dict
    
class Processor:
    def __init__(self):
        self.organizations = list()
        self.folders = list()
        self.projects = list()
        self.members = list()
        
    def add_child(self, parent, child):
        '''
        Adds a child to a parent object.
        '''
        if isinstance(parent, (Organization, Folder)):
            if isinstance(child, Project):
                parent.add_project(child)
            elif isinstance(child, Folder):
                parent.add_folder(child)
        
    def load_projects(self):
        '''
        Load the list of projects from GCP.
        '''
        my_cmd = shlex.split('gcloud projects list --format json')
        try:
            results = subprocess.check_output(my_cmd)
        except:
            logging.error("Encountered an error when running {0}".format(my_cmd))
            return
        for project in json.loads(results):
            self.projects.append(Project(project))

    def build_hierarchy(self):
        '''
        Model the hierarchy of the GCP environment.
        This function starts at the project level
        because there should always be a project.
        '''
        for project in self.projects:
            self.__load_ancestors__(project)

    def __load_ancestors__(self, child):
        '''
        Load the ancestors for a given project.
        Place the projects under the organization or folder(s).
        This is recursive, so if a project is under multiple folders,
        it should load all of the folders in order.
        '''
        ancestor_list = child.load_ancestors()
        for ancestor in ancestor_list:
            if ancestor['type'] == "folder":
                parent = self.__add_folder__(ancestor['id'])
                self.add_child(parent, child)
                child = parent
            elif ancestor['type'] == "organization":
                parent = self.__add_organization__(ancestor['id'])
                self.add_child(parent, child)
                    
    def __add_folder__(self, folder_id):
        parent_folder = self.get_folder(folder_id)
        if not parent_folder:
            my_cmd = shlex.split("gcloud resource-manager folders describe " + folder_id + " --format json")
            try:
                results = subprocess.check_output(my_cmd)
            except:
                logging.error("Encountered an error when running {0}".format(my_cmd))
                return
            parent_folder = Folder(json.loads(results))
            self.folders.append(parent_folder)
        return parent_folder

    def __add_organization__(self, organization_id):
        org = self.get_organization(organization_id)
        if not org:
            my_cmd = shlex.split("gcloud organizations describe " + organization_id + " --format json")
            try:
                results = subprocess.check_output(my_cmd)
            except:
                logging.error("Encountered an error when running {0}".format(my_cmd))
                return
            org = Organization(json.loads(results))
            self.organizations.append(org)
        return org

    def __find_member__(self, input_member):
        for member in self.members:
            if member.name == input_member:
                return member
        return None

    def traverse_hierarchy(self):
        if len(self.organizations) > 0:
            for org in self.organizations:
                self.__parse_bindings__('organization', org)
                for folder in org.get_folders():
                    self.traverse_folder(folder)
                for project in org.get_projects():
                    self.traverse_project(project)
        elif len(self.folders) > 0:
            for folder in self.folders:
                self.traverse_folder(folder)
        elif len(self.projects) > 0:
            for project in self.projects:
                self.traverse_project(project)
        else:
            logging.error("No hierarchy found, exiting.")
            sys.exit()
   
    def traverse_folder(self, folder):
        self.__parse_bindings__('folder', folder)
        child_folders = folder.get_folders()
        child_projects = folder.get_projects()
        for project in child_projects:
            self.traverse_project(project)
        for child_folder in child_folders:
            self.traverse_folder(child_folder)
    
    def traverse_project(self, project):
        self.__parse_bindings__('project', project)
        for service_account in project.get_service_accounts():
            if service_account.is_enabled():
                self.__parse_bindings__('service_account', service_account)

    def __parse_bindings__(self, scope, obj):
        if scope == 'project':
            binding_name = obj.id
        elif scope == 'service_account':
            binding_name = obj.email
        else:
            binding_name = obj.name
        if obj.get_bindings() is not None:
            for binding in obj.get_bindings():
                for id_string in binding['members']:
                    (member_type, member_name) = id_string.split(":")
                    member = self.__find_member__(member_name)
                    if member is None:
                        member = Member(member_type, member_name)
                        self.members.append(member)
                    member.add_direct_binding(scope, binding_name, binding['role'])
                        
    def get_members(self):
        return self.members

    def get_sa_members(self):
        return [ member for member in self.members if member.is_service_account_member() ]
        
    def get_projects(self):
        return self.projects

    def get_organization(self, org_id):
        for org in self.organizations:
            if org.id == org_id:
                return org

    def get_folder(self, folder_id):
        for folder in self.folders:
            if folder.id == folder_id:
                return folder
        return None

    def get_project(self, project_id):
        for project in self.projects:
            if project.id == project_id:
                return project
        
    def set_member_indirect_bindings(self, sa_list, member):
        total_bindings = dict()
        for email in sa_list:
            service_account = self.__find_member__(email)
            if service_account is not None:
                # If find_member returns none, then it didn't have any bindings
                # We only want service accounts with bindings
                total_bindings = merge_bindings(service_account.get_direct_bindings(), total_bindings)
        member.set_indirect_bindings(total_bindings)

    def get_org_names(self):
        return [ org.name for org in self.organizations ]
