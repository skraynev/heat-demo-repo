#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from heat.common import exception
from heat.openstack.common.gettextutils import _
from heat.engine import attributes
from heat.engine import constraints
from heat.engine import properties
from heat.engine import resource

import json
import requests


class ZabbixPing(resource.Resource):

    PROPERTIES = (
        ZB_SERVER, TIMEOUT, USER, PASS, SERVER_IP,
        GROUP_NAME,
    ) = (
        'zabbix_server', 'timeout', 'user', 'password', 'server_ip',
        'group_name',
    )

    properties_schema = {
        ZB_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Server name or ip.'),
            required=True
        ),
        USER: properties.Schema(
            properties.Schema.STRING,
            _('User name for zabbix auth.'),
            required=True
        ),
        PASS: properties.Schema(
            properties.Schema.STRING,
            _('Password for zabbix auth.'),
            required=True
        ),
        SERVER_IP: properties.Schema(
            properties.Schema.STRING,
            _('Server ip for provisioning.'),
            required=True
        ),
        TIMEOUT: properties.Schema(
            properties.Schema.NUMBER,
            _('timeout for request.'),
            default=10,
        ),
        GROUP_NAME: properties.Schema(
            properties.Schema.STRING,
            _('Name for host group.'),
            default='Heat_Demo',
        ),
    }
################################### CUSTOM FUNCTIONS
    def initial_client(self):
        self.session = requests.Session()
        # Default headers for all requests
        self.session.headers.update({
            'Content-Type': 'application/json-rpc',
            'User-Agent': 'python/pyzabbix'
        })

        self.req_id = 0
        self.auth_token = 0
        self.timeout = self.properties[self.TIMEOUT]
        server = self.properties[self.ZB_SERVER]
        self.url = 'http://%s/zabbix/api_jsonrpc.php' % server

    def auth_client(self):
        user = self.properties[self.USER]
        password = self.properties[self.PASS]
        params = {
            'user': user,
            'password': password
        }
        resp = self.do_request('user.login', params=params)
        self.auth_token = resp['result']

    def do_request(self, method, params=None):
        request_json = {
            'jsonrpc': '2.0',
            'method': method,
            'params': params or {},
            'id': self.req_id,
        }

        if self.auth_token:
            request_json['auth'] = self.auth_token

        response = self.session.post(
            self.url,
            data=json.dumps(request_json),
            timeout=self.timeout
        )
        response.raise_for_status()

        if not len(response.text):
            raise Exception("Received empty response")

        try:
            response_json = json.loads(response.text)
        except ValueError:
            raise Exception(
                "Unable to parse json: %s" % response.text
            )

        self.req_id += 1

        return response_json

    def create_group(self):
        gr_name = self.properties[self.GROUP_NAME]
        resp = self.do_request('hostgroup.create', params={'name': gr_name})
        return resp

    def delete_group(self, gr_id):
        resp = self.do_request(
            'hostgroup.delete', params=[{'groupid': gr_id}])
        return resp

    def create_host(self, gr_id):
        ip = self.properties[self.SERVER_IP]
        params = {
            'host': 'Heat_Demo_VM',
            'ip': ip,
            'port':10050,
            'useip':1,
            "groups":[
                {
                    "groupid": gr_id,
                }
            ]
        }
        resp = self.do_request('host.create', params=params)
        return resp

    def delete_host(self, host_id):
        resp = self.do_request(
            'host.delete', params=[{'hostid': host_id}])
        return resp

    def create_item(self, host_id):
        params={
            'description': 'Heat Demo Ping host',
            'type': 3,
            'delay': 5,
            'key_': 'icmpping',
            'hostid': host_id
        }
        resp = self.do_request('item.create', params=params)
        return resp

    def delete_item(self, item_id):
        resp = self.do_request('item.delete', params=[item_id])
        return resp
################################### REQUIRED FUNCTIONS
    def handle_create(self):
        # initialize client and get auth for requests
        self.initial_client()
        self.auth_client()

        # create group
        gr_id = self.create_group()['result']['groupids'][0]
        # create server
        host_id = self.create_host(gr_id)['result']['hostids'][0]
        # create ICMP check
        item_id = self.create_item(host_id)['result']['itemids'][0]

#        Avaliable for Juno
#        self.data_set('gr_id', gr_id)
#        self.data_set('host_id', host_id)
#        self.data_set('item_id', item_id)
        data = "%s-%s-%s" % (gr_id, host_id, item_id)
        self.resource_id_set(data)

    def parse_data(self, data):
        res = str(data).split('-')
        return {
            'gr_id': res[0],
            'host_id': res[1],
            'item_id': res[2]}

    def handle_delete(self):
#        Avaliable for Juno
#        data = self.data()
        data = self.parse_data(self.resource_id)

        if not data:
            return

        # initialize client and get auth for requests
        self.initial_client()
        self.auth_client()

        # delete ICMP check
        r3 = self.delete_item(data['item_id'])
        # delete server
        r2 = self.delete_host(data['host_id'])
        # delete group
        r1 = self.delete_group(int(data['gr_id']))

################################### MAPPING CLASS TO RESOURCE NAME
def resource_mapping():
    return {
        'OS::Zabbix::Ping': ZabbixPing,
    }
