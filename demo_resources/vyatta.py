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

import base64
import requests
import urlparse


class VyattaFirewall(resource.Resource):

    PROPERTIES = (
        V_SERVER, USER, PASS, NAME, RULE_ID, IP, PORT,
    ) = (

        'v_server', 'user', 'password', 'name', 'rule_id', 'ip', 'port',
    )

    properties_schema = {
        V_SERVER: properties.Schema(
            properties.Schema.STRING,
            _('Server ip.'),
            required=True
        ),
        USER: properties.Schema(
            properties.Schema.STRING,
            _('User name for vyatta auth.'),
            required=True
        ),
        PASS: properties.Schema(
            properties.Schema.STRING,
            _('Password for vyatta auth.'),
            required=True
        ),
        NAME: properties.Schema(
            properties.Schema.STRING,
            _('Firewall name.'),
            default='Heat_Demo'
        ),
        RULE_ID: properties.Schema(
            properties.Schema.STRING,
            _('Id for firewall rule.'),
            default='10'
        ),
        IP: properties.Schema(
            properties.Schema.STRING,
            _('Destination instance ip.'),
            required=True
        ),
        PORT: properties.Schema(
            properties.Schema.STRING,
            _('Destination port.'),
            required=True
        ),
    }

################################### CUSTOM FUNCTIONS
    def initialize(self):
        user = self.properties[self.USER]
        password = self.properties[self.PASS]
        server = self.properties[self.V_SERVER]

        auth = base64.b64encode('{username}:{password}'.format(
            username=user,
            password=password,
        ))

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Vyatta-Specification-Version': '0.1',
            'Authorization': 'Basic %s' % auth
        })

        self.base_url = 'http://%s' % server

    def configure(self):
        response = self.session.post(
            urlparse.urljoin(self.base_url, '/rest/conf')
        )
        response.raise_for_status()
        url = response.headers['Location'] + '/'
        self.base_url = urlparse.urljoin(self.base_url, url)

    def save(self):
        for command in ('commit', 'save'):
            r = self.session.post(
                urlparse.urljoin(self.base_url, command)
            )
            r.raise_for_status()

    def configure_firewall(self, name, rule, ip, port):

        firewall = 'set/firewall/name/%s/rule/%s' % (name, rule)

        create_firewall = '%s/action/accept' % firewall
        protocol = '%s/protocol/tcp' % firewall
        ip = '{0}%2F24'.format(ip)
        dest_address = '%s/destination/address/%s' % (firewall, ip)
        dest_port = '%s/destination/port/%s' % (firewall, port)

        for command in (create_firewall, protocol, dest_address, dest_port):
            r = self.session.put(
                urlparse.urljoin(self.base_url, command)
            )
            r.raise_for_status()

        self.save()

    def delete_firewall(self, name):
        firewall = 'delete/firewall/name/%s' % name
        r = self.session.put(
            urlparse.urljoin(self.base_url, firewall)
        )
        r.raise_for_status()

        self.save()
################################### REQUIRED FUNCTIONS
    def handle_create(self):
        self.initialize()
        self.configure()

        name = self.properties[self.NAME]
        rule = self.properties[self.RULE_ID]
        ip = self.properties[self.IP]
        port = self.properties[self.PORT]

        self.configure_firewall(name, rule, ip, port)
        self.resource_id_set(name)

    def handle_delete(self):
        name = self.resource_id

        if not name:
            return

        self.initialize()
        self.configure()
        self.delete_firewall(name)

################################### MAPPING CLASS TO RESOURCE NAME
def resource_mapping():
    return {
        'OS::Vyatta::Firewall': VyattaFirewall,
    }
