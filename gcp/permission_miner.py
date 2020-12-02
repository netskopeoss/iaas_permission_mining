import datetime
import logging
import argparse
import sys
import os
import json
from graph_tool import GraphTool
from processor import Processor

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

"""Main execution for the GCP permission mining project."""

def find_external_members(processor):
    """
    Look at all the members and try to determine
    if any of them are from outside the Organization.
    """
    org_list = processor.get_org_names()
    for org in org_list:
        logging.info("Looking for members outside of {0}".format(org))
    for member in processor.get_members():
        if '@' in member.name:
            suffix = member.name.split('@')[1]
            if 'gserviceaccount.com' not in suffix:
                member.set_external_member(True)
            for org_name in org_list:
                if org_name == suffix:
                    member.set_external_member(False)
        else:
            member.set_external_member(False)
    
def graph_resources(processor, graph):
    """Create graph with the overall hierarchy of resources."""
    if len(processor.organizations) > 0:
        for org in processor.organizations:
            graph.graph_organization(org)
    elif len(processor.folders) > 0:
        for folder in processor.folders:
            graph.graph_folder(folder)
    else:
        for project in processor.projects:
            graph.graph_project(project)
    return graph

def graph_members(processor, graph):
    """"Add members to the graph with privilege escalation potential."""
    sa_members = processor.get_sa_members()
    logging.info("Found {0} service account members.".format(len(sa_members)))
    for member in sa_members:
        graph.graph_member(member)
    return sa_members
        
def find_indirect_permissions(processor, graph, member_list):
    """
    Find service accounts that members can access.
    Set the indirect bindings for those members.
    """
    for member in member_list:
        service_account_list = graph.query_data(member)
        processor.set_member_indirect_bindings(service_account_list, member)
    return processor

def remove_file(file_name):
    """Removes a file."""
    if os.path.exists(file_name):
        print ("WARNING: Deleting file: {0}".format(file_name))
        os.remove(file_name)

def print_output(processor, file_name):
    """Print the output of this tool, which is JSON."""
    with open (file_name, "w") as output:
        report_list = [ member.get_member_report() for member in processor.get_members() ]
        json.dump(report_list, output)

def main():
    """Main execution function."""
    # Check for dependencies first.
    if not os.getenv('NEO4J_PASSWORD'):
        print ("Missing critical environment variable: {0}.".format("NEO4J_PASSWORD"))
        print ("Exiting.  Please set the variable and run this again.")
        sys.exit()
        
    # Process the arguments passed on the command line.
    parser = argparse.ArgumentParser()
    parser.add_argument("output_file", type=str, help="The name of output file")
    parser.add_argument("--log_file_name", default="gcp_permission_miner.log", help="The name of the log file." )
    args = parser.parse_args()
    remove_file(args.output_file)
    remove_file(args.log_file_name)
    
    # Start logging
    logging.basicConfig(filename=args.log_file_name, level=logging.INFO)
    logging.info("Started at {:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()))
    
    processor = Processor()
    graph = GraphTool()
    processor.load_projects()
    processor.build_hierarchy()
    processor.traverse_hierarchy()
    graph = graph_resources(processor, graph)
    member_list = graph_members(processor, graph)
    processor = find_indirect_permissions(processor, graph, member_list)
    find_external_members(processor)
    print_output(processor, args.output_file)
    
    logging.info("Completed at {:%Y-%m-%d %H:%M:%S}".format(datetime.datetime.now()))
        
if __name__ == "__main__":
    main()
