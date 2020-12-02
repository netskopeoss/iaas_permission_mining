import os
import sys
import logging
from py2neo import Graph, Node, Relationship, NodeMatcher
from gcp import Organization, Folder, Project, ServiceAccount, Member

"""
Copyright 2020 Netskope, Inc.
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following
disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Written by Colin Estep
"""

""""This module creates and manipulates the graph."""

class GraphTool:
    """Class to map GCP entities in the graph."""
    def __init__(self):
        """Create a graph instance."""
        self.graph = Graph(password=os.environ['NEO4J_PASSWORD'])
            
    def graph_organization(self, org):
        """Create a graph node for a GCP organization."""
        logging.info("Graphing organization " + org.name)
        org_node = Node("organization", name=org.name, id=org.id)
        org_node.__primarylabel__ = "organization"
        org_node.__primarykey__ = "name"
        for folder in org.get_folders():
            self.graph_folder(folder, org_node)
        for project in org.get_projects():
            self.graph_project(project, org_node)
        
    def graph_folder(self, folder, parent_node=None):
        """Create a graph node for a GCP folder."""
        logging.info("Graphing folder " + folder.name)
        node = Node("folder", name=folder.name, id=folder.id)
        node.__primarylabel__ = "folder"
        node.__primarykey__ = "name"
        if parent_node is not None:
            relationship = Relationship.type("child_of")
            try:
                self.graph.merge(relationship(node, parent_node))
            except ConnectionRefusedError as e:
                logging.error(str(e))
                logging.error("Unable to connect to the graph service, exiting.")
                sys.exit()
        for child_folder in folder.get_folders():
            self.graph_folder(child_folder, node)
        for project in folder.get_projects():
            self.graph_project(project, node)

    def graph_project(self, project, parent_node=None):
        """Create a graph node for a GCP project."""
        logging.info("Graphing project " + project.id)
        node = Node("project", name=project.id, number=project.number)
        node.__primarylabel__ = "project"
        node.__primarykey__ = "name"
        if parent_node is not None:
            relationship = Relationship.type("child_of")
            try:
                self.graph.merge(relationship(node, parent_node))
            except ConnectionRefusedError as e:
                logging.error(str(e))
                logging.error("Unable to connect to the graph service, exiting.")
                sys.exit()
        for service_account in project.get_service_accounts():
            self.graph_service_account(service_account, node)

    def graph_service_account(self, service_account, parent_node):
        """Create a graph node for a service account."""
        node = Node("service_account", name=service_account.email, id=service_account.id)
        node.__primarylabel__ = "service_account"
        node.__primarykey__ = "name"
        relationship = Relationship.type("sa_child_of")
        try:
            self.graph.merge(relationship(node, parent_node))
        except ConnectionRefusedError as e:
            logging.error(str(e))
            logging.error("Unable to connect to the graph service, exiting.")
            sys.exit()
        
    def graph_member(self, member):
        """Create a graph node for a member in GCP."""
        logging.info("Graphing member " + member.name)
        node = Node("member", type=member.type, name=member.name)
        node.__primarylabel__ = "member"
        node.__primarykey__ = "name"     
        for binding in member.sa_scopes:
            # 1. Parse bindings for the service account user permissions
            for key in binding.keys():
                matcher = NodeMatcher(self.graph)
                location_node = matcher.match(key, name=binding[key]).first()
                # 2. Find the Org, project, or resource node at the binding level
                if location_node is None:
                    logging.warning("No node found for {0} : {1}".format(key, binding[key]))
                    logging.warning("{0} not mapped".format(member.name))
                if location_node:
                    # 3. Create relationship with the resource node(s) and the member node
                    relationship = Relationship.type("iam_binding")
                    try:
                        self.graph.merge(relationship(node, location_node))
                    except ConnectionRefusedError as e:
                        logging.error(str(e))
                        logging.error("Unable to connect to the graph service, exiting.")
                        sys.exit()
        
    def query_data(self, member):
        """Query the graph for the service accounts accessible to this member."""
        # Case where there are multiple levels of structure under the binding
        query1 = 'MATCH (member:member {name:\"' + member.name + '\"})-[:iam_binding]-(struct) WITH struct MATCH (struct)<-[:child_of*]-(s2) WITH s2 MATCH (s2)<-[:sa_child_of]-(sa:service_account) RETURN sa.name'
        # Case where there is no levels below the structure
        query2 = 'MATCH (member:member {name: \"' + member.name + '\"})-[:iam_binding]-(struct) WITH struct MATCH (struct)<-[:sa_child_of]-(sa:service_account) RETURN sa.name'
        # Case where the binding is on the service account directly
        query3 = 'MATCH (member:member {name: \"' + member.name + '\"})-[:iam_binding]-(sa:service_account) RETURN sa.name'
        result1 = self.graph.run(query1).data()
        result2 = self.graph.run(query2).data()
        result3 = self.graph.run(query3).data()
        merged_list = result1 + result2 + result3
        # Make sure the final list being returned only has unique items
        sa_set = set( [ item['sa.name'] for item in merged_list ] )
        return list(sa_set)
