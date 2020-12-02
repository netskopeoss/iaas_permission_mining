<img src="https://www.netskope.com/wp-content/uploads/2020/03/netskope-threat-labs.png" alt="Netskope Threat Labs logo" width="200"/>
<h1>README</h1>
<h2>Permission Mining Tool for GCP</h2>
<h3>Introduction</h3>
This tool is written in Python3.  It obtains data from GCP, constructs a graph database, and traverses the graph to draw conclusions about permissions of your members.
<h3>Dependencies</h3>
There are 2 major dependencies for this tool, which it expects to exist in the environment where the code will be executed:
<h4>gcloud utility</h4>
The gcloud utility is needed to obtain all the relevant information from GCP.
<h4>Neo4j</h4>

Neo4j is what we use to create and manipulate the graph database. You must install Neo4j, and create a project and database.  <b>You must create a database at version 3.5.12 for this to work.</b> It's no problem to download the latest version of Neo4j, it will allow you to create a database at version 3.5.12.  Make sure the database is running and you are able to connect to it before using this script.  For more information, refer to their documentation here: https://neo4j.com/docs/getting-started/current/
<h3>Before Running the Tool</h3>
<h4>Required Permissions in GCP</h4>
In order to successfully run this code with all of the features currently implemented, your gcloud utility must be running as a member that has the following permissions:

- roles/iam.securityReviewer
-  roles/viewer

The permissions above will allow the script to see what resources exist in the relevant projects, as well as the IAM policies assigned to them. The code will only obtain information for projects it can list. Once it has the projects, it will attempt to discover the hierarchy above the projects.
<h4> Set the Neo4j password</h4>
By default, when you install Neo4j, it will be listening on <strong>localhost:7687</strong>, and the user you will use to connect to it is <strong>neo4j</strong>.
If you keep these defaults, you just need to set a password for the neo4j user, and then set the following environment variable, which will store the password:

> NEO4J_PASSWORD

<p>The tool will use this password to connect to the graph database and perform all operations as the neo4j user.</p>
<p>Once you are done with these steps, you are ready to run permission_miner.py.</p>

<h4>Local Write Privileges</h4>
The tool will output a JSON file with the results of the permissions found in the environment for each member. It will need enough permissions to create and write to this file.

<h3>Running the Tool</h3>
<h4>Launch</h4>
You are ready now to install the required libraries and run the tool:

    pip3 install -r requirements
    python3 permission_miner.py <output file name> --log_file_name <log name>

<h4>Output</h4>
The following files are the output of running the permission miner:

- A log file (named `gcp_permission_miner.log` by default)
- A JSON file

The JSON file contains the capabilities found for each GCP member. You can then setup your own parsing of the output to generate a formatted report or alert on certain conditions. Below is a sample of the output for a single member. Each member will have the name, type of member, external member, service account access, and admin level access. After that, each member contains the <strong>direct bindings</strong> and <strong>indirect bindings</strong> found.

The indirect bindings contain an aggregation of all permissions that the member could access. The listing of bindings show the hierarchical level at which it exists (organization, project, etc.) with the name of that resource. In addtion, the binding lists the role(s) assigned.

```json
 {
    "member": {
      "name": "colin@siftsec.com",
      "type": "user",
      "external_member": false,
      "service_account_access": true,
      "admin_level_access": true,
      "direct_bindings": {
        "organization": {
          "siftsec.com": [
            "role_name",
          ]
        },
        "folder": {
          "folder_name": [
            "role_name"
          ]
        },
        "project": {
          "project_name": [
            "role_name_1",
            "role_name_2",
            "role_name_3"
          ]
        },
        "service_account": {
          "service_account_email1": [
            "role_name"
          ],
          "service_account_email2": [
            "role_name"
          ]
        }
      },
      "indirect_bindings": {
        "organization": {
          "organization_name": [
            "role_name_1",
            "role_name_2"
          ]
        },
        "folder": {
          "folder_name": [
            "role_name"
          ]
        },
        "project": {
          "project_name1": [
            "role_name_1",
            "role_name_2"
          ],
          "project_name2": [
            "role_name_1",
            "role_name_2"
          ]
        },
        "service_account": {}
      }
    }
  }
  ```
