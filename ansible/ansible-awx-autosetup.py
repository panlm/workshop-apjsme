#!/usr/bin/env python
import base64, uuid
import os, time, sys, re
import requests
from time import localtime, strftime

pc_ip = ""
pc_user = ""
pc_pass = ""
ansible_ip = ""
if pc_ip == '' or pc_user == '' or pc_pass == '' or ansible_ip == '':
    pc_ip = os.getenv('PC_IP', "")
    token = os.getenv('PC_TOKEN', "")
    pc_user = re.sub(':.*$', '', base64.b64decode(token))
    pc_pass = re.sub('^.*:', '', base64.b64decode(token))
    ansible_ip = os.getenv('ANSIBLE_IP', "")
    if pc_ip == '' or pc_user == '' or pc_pass == '' or ansible_ip == '':
        print "No PC Environment Variable (PC_IP or PC_TOKEN or ANSIBLE_IP"
        sys.exit(9)

ansible_user = "admin"
ansible_pass = "password"
ansible_token = base64.b64encode('%s:%s' % (ansible_user, ansible_pass))
headers = {"Accept": "application/json", "Content-Type": "application/json", "Authorization": 'Basic %s' % ansible_token}

# create inventory script
script_name = "Script-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/inventory_scripts/" % (ansible_ip)
postdata = {
    "name": script_name,
    "organization": 1,
    "script": "#!/usr/bin/env python\n\"\"\"\nPrismCentral external inventory script\n======================================\n\nGenerates Ansible inventory of PrismCentral AHV VMs.\n\nIn addition to the --list and --host options used by Ansible, there are options\nfor generating JSON of other PrismCentral data. This is useful when creating\nVMs. For example, --clusters will return all the PrismCentral Clusters.\nThis information can also be easily found in the cache file, whose default\nlocation is /tmp/ansible-prism_central.cache).\n\nThe --pretty option pretty-prints the output for better human readability.\n\n----\nAlthough the cache stores all the information received from PrismCentral,\nthe cache is not used for current VM information (in --list, --host,\n--all, and --vms). This is so that accurate VM information is always\nfound. You can force this script to use the cache with --force-cache.\n\n----\nConfiguration is read from `prism_central.ini`, then from environment variables,\nand then from command-line arguments.\n\nMost notably, the PrismCentral IP and Credentials must be specified. It can be specified\nin the INI file or with the following environment variables:\n    export PC_IP_ADDR='1.2.3.4'\n    export PC_USERNAME='user'\n    export PC_PASSWORD='password'\n\nAlternatively, it can be passed on the command-line with --ip-addr (-i) --username (-u) --password (-p).\n\nIf you specify PrismCentral credentials in the INI file, a handy way to\nget them into your environment (e.g., to use the prism_central module)\nis to use the output of the --env option with export:\n    export $(prism_central.py --env)\n\n----\nThe following groups are generated from --list:\n - UUID    (VM UUID)\n - NAME  (VM NAME)\n - prism_central\n - cluster_NAME\n - project_NAME\n - owner_NAME\n - hypervisor_NAME\n - status_STATUS\n - category_NAME_VALUES\n\n-----\n```\nusage: prism_central.py [-h] [--list] [--host HOST] [--all] [--vms]\n                        [--clusters] [--projects] [--categories] [--nodes]\n                        [--pretty]\n                        [--cache-path CACHE_PATH]\n                        [--cache-max_age CACHE_MAX_AGE] [--force-cache]\n                        [--refresh-cache] [--env] [--ip-addr PC_IP_ADDR]\n                        [--username PC_USERNAME] [--password PC_PASSWORD]\n\nProduce an Ansible Inventory file based on PrismCentral credentials\n\noptional arguments:\n  -h, --help            show this help message and exit\n  --list                List all active VMs as Ansible inventory\n                        (default: True)\n  --host HOST           Get all Ansible inventory variables about a specific\n                        VM\n  --all                 List all PrismCentral information as JSON\n  --vms, -v             List VMs as JSON\n  --clusters            List Clusters as JSON\n  --projects            List Projects as JSON\n  --categories          List Categories as JSON\n  --nodes               List Nodes as JSON\n  --pretty              Pretty-print results\n  --cache-path CACHE_PATH\n                        Path to the cache files (default: .)\n  --cache-max_age CACHE_MAX_AGE\n                        Maximum age of the cached items (default: 0)\n  --force-cache         Only use data from the cache\n  --refresh-cache, -r   Force refresh of cache by making API requests to\n                        PrismCentral (default: False - use cache files)\n  --env, -e             Display PC_IP_ADDR, PC_USERNAME and PC_PASSWORD\n  --ip-addr PC_IP_ADDR, -i PC_IP_ADDR\n                        PrismCentral IP Address\n  --username PC_USERNAME, -u PC_USERNAME\n                        PrismCentral Username\n  --password PC_PASSWORD, -p PC_PASSWORD\n                        PrismCentral Password\n```\n\n\"\"\"\n\n# (c) 2018, Jose Gomez <jose.gomez@nutanix.com>\n#\n# Inspired by the DigitalOcean inventory plugin:\n# https://raw.githubusercontent.com/ansible/ansible/devel/contrib/inventory/digital_ocean.py\n\n######################################################################\n\n\nimport urllib2\nimport base64\nimport socket\nimport sys\nimport pprint\nimport time\nimport ssl\nimport argparse\nimport ast\nimport os\nimport re\n\nfrom time import time\n\ntry:\n    import ConfigParser\nexcept ImportError:\n    import configparser as ConfigParser\n\nimport json\n\n# socket timeout in seconds\nTIMEOUT = 60\nsocket.setdefaulttimeout(TIMEOUT)\npp = pprint.PrettyPrinter(indent=4)\n\n\nclass PcManager():\n\n    def __init__(self, ip_addr, username, password):\n        # Initialise the options.\n        self.ip_addr = ip_addr\n        self.username = username\n        self.password = password\n        self.rest_params_init()\n\n    # Initialize REST API parameters\n    def rest_params_init(self, sub_url=\"\", method=\"\",\n                         body=None, content_type=\"application/json\", response_file=None):\n        self.sub_url = sub_url\n        self.body = body\n        self.method = method\n        self.content_type = content_type\n        self.response_file = response_file\n\n    # Create a REST client session.\n    def rest_call(self):\n        base_url = 'https://%s:9440/api/nutanix/v3/%s' % (\n            self.ip_addr, self.sub_url)\n        if self.body and self.content_type == \"application/json\":\n            self.body = json.dumps(self.body)\n        request = urllib2.Request(base_url, data=self.body)\n        base64string = base64.encodestring(\n            '%s:%s' %\n            (self.username, self.password)).replace(\n            '\\n', '')\n        request.add_header(\"Authorization\", \"Basic %s\" % base64string)\n\n        request.add_header(\n            'Content-Type',\n            '%s; charset=utf-8' %\n            self.content_type)\n        request.get_method = lambda: self.method\n\n        try:\n            if sys.version_info >= (2, 7, 5):\n                ssl_context = ssl._create_unverified_context()\n                response = urllib2.urlopen(request, context=ssl_context)\n            else:\n                response = urllib2.urlopen(request)\n            result = \"\"\n            if self.response_file:\n                chunk = 16 * 1024\n                with open(self.response_file, \"wb\") as of:\n                    while True:\n                        content = response.read(chunk)\n                        if not content:\n                            break\n                        of.write(content)\n            else:\n                result = response.read()\n                if result:\n                    result = json.loads(result)\n            return result\n        except urllib2.HTTPError as e:\n            err_result = e.read()\n            if err_result:\n                try:\n                    err_result = json.loads(err_result)\n                except:\n                    print \"Error: %s\" % e\n                    return \"408\", None\n            return \"408\", err_result\n        except Exception as e:\n            print \"Error: %s\" % e\n            return \"408\", None\n\n    def list_vms(self):\n        body = {\n            \"length\": 15000,\n            \"offset\": 0,\n            \"filter\": \"\"\n        }\n        self.rest_params_init(sub_url=\"vms/list\", method=\"POST\", body=body)\n        return self.rest_call()\n\n    def list_clusters(self):\n        body = {\n            \"length\": 1000,\n            \"offset\": 0,\n            \"filter\": \"\"\n        }\n        self.rest_params_init(sub_url=\"clusters/list\", method=\"POST\", body=body)\n        return self.rest_call()\n\n    def list_projects(self):\n        body = {\n            \"length\": 1000,\n            \"offset\": 0,\n            \"filter\": \"\"\n        }\n        self.rest_params_init(sub_url=\"projects/list\", method=\"POST\", body=body)\n        return self.rest_call()\n\n    def list_categories(self):\n        body = {}\n        self.rest_params_init(sub_url=\"categories/list\", method=\"POST\", body=body)\n        return self.rest_call()\n\n    def list_nodes(self):\n        body = {\n            \"length\": 15000,\n            \"offset\": 0,\n            \"filter\": \"\"\n        }\n        self.rest_params_init(sub_url=\"hosts/list\", method=\"POST\", body=body)\n        return self.rest_call()\n\n    def get_vm(self, vm_uuid):\n        sub_url = 'vms/%s' % vm_uuid\n        self.rest_params_init(sub_url=sub_url, method=\"GET\")\n        return self.rest_call()\n\n    def search(self, user_query):\n        body = {\n            \"user_query\": str(user_query),\n            \"explicit_query\": True,\n            \"generate_autocompletions_only\": True,\n            \"is_autocomplete_selection\": False\n        }\n        self.rest_params_init(sub_url=\"search\", method=\"POST\", body=body)\n        return self.rest_call()\n\nclass PrismCentralInventory(object):\n\n    ###########################################################################\n    # Main execution path\n    ###########################################################################\n\n    def __init__(self):\n        \"\"\"Main execution path \"\"\"\n\n        # PrismCentralInventory data\n        self.data = {}  # All PrismCentral data\n        self.inventory = {}  # Ansible Inventory\n\n        # Define defaults\n        self.cache_path = '.'\n        self.cache_max_age = 0\n        self.group_variables = {}\n\n        # Read settings, environment variables, and CLI arguments\n        self.read_settings()\n        self.read_environment()\n        self.read_cli_args()\n\n        # Verify Prism Central IP was set\n        if not hasattr(self, 'ip_addr'):\n            msg = 'Could not find values for PrismCentral ip_addr. They must be specified via either ini file, ' \\\n                  'command line argument (--ip-addr, -i), or environment variables (PC_IP_ADDR)\\n'\n            sys.stderr.write(msg)\n            sys.exit(-1)\n\n        # Verify credentials were set\n        if not hasattr(self, 'username'):\n            msg = 'Could not find values for PrismCentral username. They must be specified via either ini file, ' \\\n                  'command line argument (--username, -u), or environment variables (PC_USERNAME)\\n'\n            sys.stderr.write(msg)\n            sys.exit(-1)\n        if not hasattr(self, 'password'):\n            msg = 'Could not find values for PrismCentral password. They must be specified via either ini file, ' \\\n                  'command line argument (--password, -p), or environment variables (PC_PASSWORD)\\n'\n            sys.stderr.write(msg)\n            sys.exit(-1)\n\n        # env command, show PrismCentral credentials\n        if self.args.env:\n            print(\"PC_IP_ADDR=%s\" % self.ip_addr)\n            print(\"PC_USERNAME=%s\" % self.username)\n            print(\"PC_PASSWORD=%s\" % self.password)\n            sys.exit(0)\n\n        # Manage cache\n        self.cache_filename = self.cache_path + \"/ansible-prism_central.cache\"\n        self.cache_refreshed = False\n\n        if self.is_cache_valid():\n            self.load_from_cache()\n            if len(self.data) == 0:\n                if self.args.force_cache:\n                    sys.stderr.write('Cache is empty and --force-cache was specified\\n')\n                    sys.exit(-1)\n\n        self.manager = PcManager(self.ip_addr, self.username, self.password)\n\n        # Pick the json_data to print based on the CLI command\n        if self.args.vms:\n            self.load_from_prism_central('vms')\n            json_data = {'vms': self.data['vms']}\n        elif self.args.clusters:\n            self.load_from_prism_central('clusters')\n            json_data = {'clusters': self.data['clusters']}\n        elif self.args.projects:\n            self.load_from_prism_central('projects')\n            json_data = {'projects': self.data['projects']}\n        elif self.args.categories:\n            self.load_from_prism_central('categories')\n            json_data = {'categories': self.data['categories']}\n        elif self.args.nodes:\n            self.load_from_prism_central('nodes')\n            json_data = {'nodes': self.data['nodes']}\n        elif self.args.all:\n            self.load_from_prism_central()\n            json_data = self.data\n        elif self.args.host:\n            json_data = self.load_vm_variables_for_host()\n        else:    # '--list' this is last to make it default\n            self.load_from_prism_central('vms')\n            self.build_inventory()\n            json_data = self.inventory\n\n        if self.cache_refreshed:\n            self.write_to_cache()\n\n        if self.args.pretty:\n            print(json.dumps(json_data, indent=2))\n        else:\n            print(json.dumps(json_data))\n\n    ###########################################################################\n    # Script configuration\n    ###########################################################################\n\n    def read_settings(self):\n        \"\"\" Reads the settings from the prism_central.ini file \"\"\"\n        config = ConfigParser.ConfigParser()\n        config_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'prism_central.ini')\n        config.read(config_path)\n\n        # Prism Central IP\n        if config.has_option('prism_central', 'ip_addr'):\n            self.ip_addr = config.get('prism_central', 'ip_addr')\n\n        # Credentials\n        if config.has_option('prism_central', 'username'):\n            self.username = config.get('prism_central', 'username')\n        if config.has_option('prism_central', 'password'):\n            self.password = config.get('prism_central', 'password')\n\n        # Cache related\n        if config.has_option('prism_central', 'cache_path'):\n            self.cache_path = config.get('prism_central', 'cache_path')\n        if config.has_option('prism_central', 'cache_max_age'):\n            self.cache_max_age = config.getint('prism_central', 'cache_max_age')\n\n        # Group variables\n        if config.has_option('prism_central', 'group_variables'):\n            self.group_variables = ast.literal_eval(config.get('prism_central', 'group_variables'))\n\n    def read_environment(self):\n        \"\"\" Reads the settings from environment variables \"\"\"\n        # Setup PC IP\n        if os.getenv(\"PC_IP_ADDR\"):\n            self.ip_addr = os.getenv(\"PC_IP_ADDR\")\n        # Setup credentials\n        if os.getenv(\"PC_USERNAME\"):\n            self.username = os.getenv(\"PC_USERNAME\")\n        if os.getenv(\"PC_PASSWORD\"):\n            self.password = os.getenv(\"PC_PASSWORD\")\n\n    def read_cli_args(self):\n        \"\"\" Command line argument processing \"\"\"\n        parser = argparse.ArgumentParser(description='Produce an Ansible Inventory file based on PrismCentral credentials')\n\n        parser.add_argument('--list', action='store_true', help='List all active VMs as Ansible inventory (default: True)')\n        parser.add_argument('--host', action='store', help='Get all Ansible inventory variables about a specific VM')\n\n        parser.add_argument('--all', action='store_true', help='List all PrismCentral information as JSON')\n        parser.add_argument('--vms', '-v', action='store_true', help='List all PrismCentral VMs as JSON')\n        parser.add_argument('--clusters', action='store_true', help='List Clusters as JSON')\n        parser.add_argument('--projects', action='store_true', help='List Projects as JSON')\n        parser.add_argument('--categories', action='store_true', help='List Categories as JSON')\n        parser.add_argument('--nodes', action='store_true', help='List Nodes as JSON')\n\n        parser.add_argument('--pretty', action='store_true', help='Pretty-print results')\n\n        parser.add_argument('--cache-path', action='store', help='Path to the cache files (default: .)')\n        parser.add_argument('--cache-max_age', action='store', help='Maximum age of the cached items (default: 0)')\n        parser.add_argument('--force-cache', action='store_true', default=False, help='Only use data from the cache')\n        parser.add_argument('--refresh-cache', '-r', action='store_true', default=False,\n                            help='Force refresh of cache by making API requests to PrismCentral (default: False - use cache files)')\n\n        parser.add_argument('--env', '-e', action='store_true', help='Display PC_IP_ADDR, PC_USERNAME, PC_PASSWORD')\n        parser.add_argument('--ip-addr', '-i', action='store', help='PrismCentral IP Address')\n        parser.add_argument('--username', '-u', action='store', help='PrismCentral Username')\n        parser.add_argument('--password', '-p', action='store', help='PrismCentral Password')\n\n\n\n        self.args = parser.parse_args()\n\n        if self.args.ip_addr:\n            self.ip_addr = self.args.ip_addr\n        if self.args.username:\n            self.username = self.args.username\n        if self.args.password:\n            self.password = self.args.password\n\n        # Make --list default if none of the other commands are specified\n        if (not self.args.vms and\n                not self.args.all and not self.args.host):\n            self.args.list = True\n\n    ###########################################################################\n    # Data Management\n    ###########################################################################\n\n    def load_from_prism_central(self, resource=None):\n        \"\"\"Get JSON from PrismCentral API \"\"\"\n        if self.args.force_cache and os.path.isfile(self.cache_filename):\n            return\n        # We always get fresh vms\n        if self.is_cache_valid() and not (resource == 'vms' or resource is None):\n            return\n        if self.args.refresh_cache:\n            resource = None\n\n        if resource == 'vms' or resource is None:\n            self.data['vms'] = self.manager.list_vms()\n            self.cache_refreshed = True\n        if resource == 'clusters' or resource is None:\n            self.data['clusters'] = self.manager.list_clusters()\n            self.cache_refreshed = True\n        if resource == 'projects' or resource is None:\n            self.data['projects'] = self.manager.list_projects()\n            self.cache_refreshed = True\n        if resource == 'categories' or resource is None:\n            self.data['categories'] = self.manager.list_categories()\n            self.cache_refreshed = True\n        if resource == 'nodes' or resource is None:\n            self.data['nodes'] = self.manager.list_nodes()\n            self.cache_refreshed = True\n\n    def add_inventory_group(self, key):\n        \"\"\" Method to create group dict \"\"\"\n        host_dict = {'hosts': [], 'vars': {}}\n        self.inventory[key] = host_dict\n        return\n\n    def add_host(self, group, host):\n        \"\"\" Helper method to reduce host duplication \"\"\"\n        if group not in self.inventory:\n            self.add_inventory_group(group)\n\n        if host not in self.inventory[group]['hosts']:\n            self.inventory[group]['hosts'].append(host)\n        return\n\n    def build_inventory(self):\n        \"\"\" Build Ansible inventory of vms \"\"\"\n        self.inventory = {\n            'all': {\n                'hosts': [],\n                'vars': self.group_variables\n            },\n            '_meta': {'hostvars': {}}\n        }\n\n        # add all vms by id and name\n        for vm in self.data['vms']['entities']:\n            for net in vm['status']['resources']['nic_list']:\n                if net['ip_endpoint_list']:\n                    dest = net['ip_endpoint_list'][0]['ip']\n                else:\n                    continue\n\n            self.inventory['all']['hosts'].append(dest)\n\n            self.add_host(vm['metadata']['uuid'], dest)\n\n            self.add_host(vm['status']['name'], dest)\n\n            ## will get some vm without project_reference/owner_reference in metadata\n            try:\n                ## groups that are always present\n                for group in (['prism_central',\n                               'cluster_' + vm['status']['cluster_reference']['name'].lower(),\n                               'project_' + vm['metadata']['project_reference']['name'].lower(),\n                               'owner_' + vm['metadata']['owner_reference']['name'].lower(),\n                               'hypervisor_' + vm['status']['resources']['hypervisor_type'].lower(),\n                               'status_' + vm['status']['resources']['power_state'].lower()]):\n                    self.add_host(group, dest)\n            except KeyError:\n                for group in (['prism_central',\n                               'cluster_' + vm['status']['cluster_reference']['name'].lower(),\n                               'project_' + '',\n                               'owner_' + '',\n                               'hypervisor_' + vm['status']['resources']['hypervisor_type'].lower(),\n                               'status_' + vm['status']['resources']['power_state'].lower()]):\n                    self.add_host(group, dest)\n\n            ## groups that are not always present\n            for group in (vm['metadata']['categories']):\n                if group:\n                    category = 'category_' + group.lower() + \"_\" + PrismCentralInventory.to_safe(vm['metadata']['categories'][group]).lower()\n                    self.add_host(category, dest)\n\n            #if vm['labels']:\n            #    for tag in vm['labels']:\n            #        self.add_host(tag, dest)\n\n            # hostvars\n            #info = self.pc_namespace(vm)\n            self.inventory['_meta']['hostvars'][dest] = vm\n\n    def load_vm_variables_for_host(self):\n        \"\"\" Generate a JSON response to a --host call \"\"\"\n        host = self.args.host\n        result = self.manager.search(host)\n        vm_uuid = result['query_term_list'][0]['token_list'][0]['identifier']['value']\n        vm = self.manager.get_vm(vm_uuid)\n        #info = self.pc_namespace(vm)\n        return {'vm': vm}\n\n    ###########################################################################\n    # Cache Management\n    ###########################################################################\n\n    def is_cache_valid(self):\n        \"\"\" Determines if the cache files have expired, or if it is still valid \"\"\"\n        if os.path.isfile(self.cache_filename):\n            mod_time = os.path.getmtime(self.cache_filename)\n            current_time = time()\n            if (mod_time + self.cache_max_age) > current_time:\n                return True\n        return False\n\n    def load_from_cache(self):\n        \"\"\" Reads the data from the cache file and assigns it to member variables as Python Objects \"\"\"\n        try:\n            with open(self.cache_filename, 'r') as cache:\n                json_data = cache.read()\n            data = json.loads(json_data)\n        except IOError:\n            data = {'data': {}, 'inventory': {}}\n\n        self.data = data['data']\n        self.inventory = data['inventory']\n\n    def write_to_cache(self):\n        \"\"\" Writes data in JSON format to a file \"\"\"\n        data = {'data': self.data, 'inventory': self.inventory}\n        json_data = json.dumps(data, indent=2)\n\n        with open(self.cache_filename, 'w') as cache:\n            cache.write(json_data)\n\n    ###########################################################################\n    # Utilities\n    ###########################################################################\n    @staticmethod\n    def to_safe(word):\n        \"\"\" Converts 'bad' characters in a string to underscores so they can be used as Ansible groups \"\"\"\n        return re.sub(r\"[^A-Za-z0-9\\-.]\", \"_\", word)\n\n    #@staticmethod\n    #def pc_namespace(data):\n    #    \"\"\" Returns a copy of the dictionary with all the keys put in a 'pc_' namespace \"\"\"\n    #    info = {}\n    #    for k, v in data.items():\n    #        info['pc_' + k] = v\n    #    return info\n\n\n###########################################################################\n# Run the script\nPrismCentralInventory()\n"
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    script_id = r.json()["id"]
    print "script_id:%d" % (script_id)
else:
    print r.status_code
    print r.text

# create inventory
inventory_name = "Inv-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/inventories/" % (ansible_ip)
postdata = {
    "name": inventory_name,
    "organization":1,
    "variables":"---"
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    inventory_id = r.json()["id"]
    print "inventory_id:%d" % (inventory_id)
else:
    print r.status_code
    print r.text

# create inventory source to link inventory and inventory script
inventory_source_name = "InvSrc-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/inventory_sources/" % (ansible_ip)
postdata = {
    "name": inventory_source_name,
    "inventory": inventory_id,
    "source_script": script_id,
    "credential": None,
    "overwrite_vars": False,
    "update_on_launch": True,
    "verbosity": 1,
    "update_cache_timeout": 0,
    "custom_virtualenv": None,
    "source_regions": "",
    "source_vars": "---\nPC_IP_ADDR: %s\nPC_USERNAME: %s\nPC_PASSWORD: %s" % (pc_ip, pc_user, pc_pass),
    "source": "custom"
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    inventory_source_id = r.json()["id"]
    print "inventory_source_id:%d" % (inventory_source_id)
else:
    print r.status_code
    print r.text

# refresh inventory source
url = "http://%s/api/v2/inventory_sources/%d/update/" % (ansible_ip, inventory_source_id)
postdata = {
    "extra_vars": {}
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    print r.status_code
else:
    print r.status_code
    print r.text

# get credential type id for "machine"
url = "http://%s/api/v2/credential_types/" % (ansible_ip)
r = requests.get(url, headers=headers, verify=False)
if r.ok:
    full = r.json()["results"]
    for f in full:
        if f["name"] == "Machine":
            credential_type_id = f["id"]
    print "credential_type_id:%d" % (credential_type_id)
else:
    print r.status_code
    print r.text

# create credential
credential_name = "Cred-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/credentials/" % (ansible_ip)
postdata = {
    "credential_type": credential_type_id,
    "description": "",
    "inputs": {
        "become_method": "sudo",
        "become_username": "root",
        "ssh_key_data": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAsvftfW1XYzdlHrf4wmQ+0vtBkAZb9HjrtrXCqseaf8FoX4k/DQ9F\nN3pJRtVJU020QPtbKgR5MaA9BnS7EldCLK/t0dxZSYJ+7oXdCMyDY2jfTz+yNg+FAEwL1K\nXtd76obEsTxBGocPT3q7sjwAaKWZ2ZIXKhxPsfxR3gRH9nWqpmf2JeZ5Xo1HeXpePSpEvs\nCgo38E5qyA2Bm2ALav/bgKXTcbMsvRAoFcrrnuZSM4l51e0eP2T3TgfqWYu0+EnOwcrR1u\nQv4KNLT6AOoz5DtfWcg1fcs+olOMdh6OxUTj928Vd7GRpkzNoyaznAHd0aLJtrCRGmMUj9\nkwazChBSSwAAA+DCI0mlwiNJpQAAAAdzc2gtcnNhAAABAQCy9+19bVdjN2Uet/jCZD7S+0\nGQBlv0eOu2tcKqx5p/wWhfiT8ND0U3eklG1UlTTbRA+1sqBHkxoD0GdLsSV0Isr+3R3FlJ\ngn7uhd0IzINjaN9PP7I2D4UATAvUpe13vqhsSxPEEahw9PeruyPABopZnZkhcqHE+x/FHe\nBEf2daqmZ/Yl5nlejUd5el49KkS+wKCjfwTmrIDYGbYAtq/9uApdNxsyy9ECgVyuue5lIz\niXnV7R4/ZPdOB+pZi7T4Sc7BytHW5C/go0tPoA6jPkO19ZyDV9yz6iU4x2Ho7FROP3bxV3\nsZGmTM2jJrOcAd3Rosm2sJEaYxSP2TBrMKEFJLAAAAAwEAAQAAAQAorCuu66CGjdpPRuQj\n2YBllnBp+OgBAVIgbeJVyZMVIbFEtP49S5EhcIsiq+pEIk6qzfUD8YxReOclhnXVTztcyI\na1wOwRxrRuJMH88+2QNA88BW/M1W4WiTHPG/6BzjScl9tgHds4AJQg1SDkzRe4EhbxAQo+\nqAuqUoXbS1EDy4C96QJIzhI7UiJi139rLxKJSlazl0vUVu9eGxwvVGSh/dP5e2Aqawl7hN\n2evcyQY7aR8Q7POn7bZxN3rEeA8ZXMZjQH1PpRiwrixD83skBhXYIKFL2TJmwaLOKhn3Bm\nDrqMCDIW3JUE5T06B/hsJ6efCsKCkKkNsSz6BU2stOmxAAAAgQCOilL8t3QF90w16HyAIL\nXZrk9JXE+4NtlS4tlzgGZNjOTBTuhMglqNxoivBaRpvaKnVttAC/YEBLqJfGmWhiDOOJK5\njpxXZPYLrUo6f5JdUFHdTSV3YD2QaeXEyxXicM9n2gX5tuSv+7NnQnltRo3nV6IDgAMnij\ndraZ9wVZohxAAAAIEA2a/RVmWH/elLdUKOqCm4KmFbDud4Vb/RJUBFUSHUfW66meKJQ4Z9\njN4x7deXgCoZX0eEw6TrNH6sEcpNvfOQ1geinwq/yb0II+hStwMmpJwXPPWxqSx91XPyux\nZHjty3Tyr/jWidjEUhuhYTLgiYUbXrlqhI56NAqtcqEtYzrycAAACBANJ3mhpv2JUOpHTO\nNeEKFvDrh+/nApMzBWXt0Ga1pqQw4kmf81PaFHJ4xN7HJV/nicQst3mj6Bt31oUUw4fksx\nSbSYBrHXPP15R7kIxTPG/otmdl7mW4X/u+NqT9/ar7f7A8RpD+Kp6vE7PZuCVzsu2uXqzJ\nyJQ7SPBlrPxL4Xo9AAAAJnN0ZXZlbnBhbkBzdGV2ZW5wYW5zLU1hY0Jvb2stUHJvLmxvY2\nFsAQIDBA==\n-----END OPENSSH PRIVATE KEY-----",
        "username": "centos"
    },
    "name": credential_name,
    "organization": 1,
    "user": 1
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    credential_id = r.json()["id"]
    print "credential_id:%d" % (credential_id)
else:
    print r.status_code
    print r.text

# create project
project_name = "Proj-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/projects/" % (ansible_ip)
postdata = {
    "name": project_name,
    "organization": 1,
    "scm_type": "git",
    "base_dir": "/var/lib/awx/projects",
    "scm_url": "https://github.com/ansible/ansible-tower-samples",
    "scm_update_on_launch": True,
    "scm_update_cache_timeout": "0",
    "custom_virtualenv":None
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    project_id = r.json()["id"]
    print "project_id:%d" % (project_id)
else:
    print r.status_code
    print r.text

# update project
url = "http://%s/api/v2/projects/%d/update/" % (ansible_ip, project_id)
postdata = {"extra_vars":{}}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    update_id = r.json()["id"]
    print "update_id:%d" % (update_id)
else:
    print r.status_code
    print r.text

status = ""
while True:
    time.sleep(2)
    if status == "successful":
        break
    else:
        url = "http://%s/api/v2/project_updates/%d" % (ansible_ip, update_id)
        r = requests.get(url, headers=headers, verify=False)
        if r.ok:
            status = r.json()["status"]
            print status
        else:
            print r.status_code

# create template
random_string = str(uuid.uuid4())
template_name = "JobTemplate-%s" % (strftime("%Y%m%d-%H%M%S", localtime()))
url = "http://%s/api/v2/job_templates/" % (ansible_ip)
postdata = {
    "allow_callbacks": True,
    "ask_credential_on_launch": False,
    "ask_diff_mode_on_launch": False,
    "ask_inventory_on_launch": False,
    "ask_job_type_on_launch": False,
    "ask_limit_on_launch": False,
    "ask_skip_tags_on_launch": False,
    "ask_tags_on_launch": False,
    "ask_variables_on_launch": False,
    "ask_verbosity_on_launch": False,
    "custom_virtualenv": None,
    "extra_vars": "",
    "forks": 0,
    "host_config_key": random_string,
    "inventory": inventory_id,
    "job_slice_count": 1,
    "job_tags": "",
    "job_type": "run",
    "name": template_name,
    "playbook": "hello_world.yml",
    "project": project_id,
    "skip_tags": "",
    "survey_enabled": False,
    "timeout": 0,
    "verbosity": 0
}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    template_id = r.json()["id"]
    print "template_id:%d" % (template_id)
    # get host key & callback url
    callback = r.json()["related"]["callback"]
    print "callback: http://%s%s" % (ansible_ip, callback)
    host_config_key = r.json()["host_config_key"]
    print "host_config_key:%s" % (host_config_key)
else:
    print r.status_code
    print r.text

# add credential to template
url = "http://%s/api/v2/job_templates/%d/credentials/" % (ansible_ip, template_id)
postdata = {"id": credential_id}
r = requests.post(url, headers=headers, verify=False, json=postdata)
if r.ok:
    print r.status_code
else:
    print r.status_code
    print r.text


