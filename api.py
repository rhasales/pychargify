# -*- coding: utf-8 -*-
'''
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


Created on Nov 20, 2009
Author: Paul Trippett (paul@pyhub.com)
'''

from http import client as httplib
import base64
import datetime
import urllib
from decimal import Decimal

import iso8601
from itertools import chain
from xml.dom import minidom

try:
    import json
except Exception as e:
    try:
        import simplejson as json
    except Exception as e:
        try:
            # For AppEngine users
            import django.utils.simplejson as json
        except Exception as e:
            print("No Json library found... Exiting.")
            exit()


class ChargifyError(Exception):
    """
    A Chargify Releated error
    @license    GNU General Public License
    """
    pass


class ChargifyUnAuthorized(ChargifyError):
    """
    Returned when API authentication has failed.
    @license    GNU General Public License
    """
    pass


class ChargifyForbidden(ChargifyError):
    """
    Returned by valid endpoints in our application that have not been
    enabled for API use.
    @license    GNU General Public License
    """
    pass


class ChargifyNotFound(ChargifyError):
    """
    The requested resource was not found.
    @license    GNU General Public License
    """
    pass


class ChargifyUnProcessableEntity(ChargifyError):
    """
    Sent in response to a POST (create) or PUT (update) request
    that is invalid.
    @license    GNU General Public License
    """
    pass


class ChargifyServerError(ChargifyError):
    """
    Signals some other error
    @license    GNU General Public License
    """
    pass


class ChargifyBase(object):
    """
    The ChargifyBase class provides a common base for all classes
    in this module
    @license    GNU General Public License
    """
    __ignore__ = ['api_key', 'sub_domain', 'base_host', 'request_host',
                  'id', '__xmlnodename__']

    __single_value_attribute_types__ = {}

    api_key = ''
    sub_domain = ''
    base_host = '.chargify.com'
    request_host = ''
    id = None

    def __init__(self, apikey, subdomain):
        """
        Initialize the Class with the API Key and SubDomain for Requests
        to the Chargify API
        """
        self.api_key = apikey
        self.sub_domain = subdomain
        self.request_host = self.sub_domain + self.base_host

    def __get_xml_value(self, nodelist):
        """
        Get the Text Value from an XML Node
        """
        rc = ""
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rc = rc + node.data
        return rc

    def __get_object_from_node(self, node, obj_type=''):
        """
        Copy values from a node into a new Object
        """
        if obj_type == '':
            constructor = globals()[self.__name__]
        else:
            constructor = globals()[obj_type]
        obj = constructor(self.api_key, self.sub_domain)

        for childnodes in node.childNodes:
            if childnodes.nodeType == 1 and not childnodes.nodeName == '':
                if childnodes.nodeName in self.__attribute_types__:
                    obj.__setattr__(childnodes.nodeName,
                                    self._applyS(childnodes.toxml(),
                                                 self.__attribute_types__[childnodes.nodeName],
                                                 childnodes.nodeName))
                elif "type" in childnodes.attributes.keys() and childnodes.attributes["type"].nodeValue == "array":
                    children = list()
                    for subChildNode in childnodes.childNodes:
                        children.append(self.__get_object_from_node(subChildNode, self.__attribute_types__.get(
                            subChildNode.nodeName)))

                    obj.__setattr__(childnodes.nodeName, children)

                else:
                    node_value = self.__get_xml_value(childnodes.childNodes)
                    if "type" in childnodes.attributes.keys():
                        node_type = childnodes.attributes["type"]
                        if node_value:
                            if node_type.nodeValue == 'datetime':
                                node_value = datetime.datetime.fromtimestamp(
                                    iso8601.parse(node_value))
                            elif node_type.nodeValue == 'integer':
                                node_value = int(node_value)
                            elif node_type.nodeValue == 'boolean':
                                node_value = True if node_value == "true" else False
                            elif node_type.nodeValue == 'decimal':
                                node_value = Decimal(node_value)
                    elif obj.__single_value_attribute_types__.has_key(childnodes.nodeName):
                        node_value = obj.__single_value_attribute_types__.get(childnodes.nodeName)(node_value)

                    obj.__setattr__(childnodes.nodeName, node_value)
        return obj

    def fix_xml_encoding(self, xml):
        """
        Chargify encodes non-ascii characters in CP1252.
        Decodes and re-encodes with xml characters.
        Strips out whitespace "text nodes".
        """
        return str(''.join([i.strip() for i in xml.split('\n')])).encode(
            'CP1252', 'replace').decode('utf-8', 'ignore').encode(
            'ascii', 'xmlcharrefreplace')

    def _applyS(self, xml, obj_type, node_name):
        """
        Apply the values of the passed xml data to the a class
        """
        dom = minidom.parseString(self.fix_xml_encoding(xml))
        nodes = dom.getElementsByTagName(node_name)
        if nodes.length == 1:
            return self.__get_object_from_node(nodes[0], obj_type)

    def _applyA(self, xml, obj_type, node_name):
        """
        Apply the values of the passed data to a new class of the current type
        """
        dom = minidom.parseString(self.fix_xml_encoding(xml))
        nodes = dom.getElementsByTagName(node_name)
        objs = []
        for node in nodes:
            objs.append(self.__get_object_from_node(node, obj_type))
        return objs

    def _toxml(self, dom):
        """
        Return a XML Representation of the object
        """
        element = minidom.Element(self.__xmlnodename__)
        for property, value in self.__dict__.iteritems():
            if not property in self.__ignore__:
                if property in self.__attribute_types__:
                    if isinstance(value, list):

                        child = minidom.Element(property)

                        for item in value:
                            child.appendChild(item._toxml(dom))

                        element.appendChild(child)

                    else:
                        element.appendChild(value._toxml(dom))
                else:
                    node = minidom.Element(property)

                    if type(value) == bool:
                        value = "true" if value else "false"
                        node.setAttribute("type", "boolean")

                    elif type(value) == int:
                        node.setAttribute("type", "integer")

                    node_txt = dom.createTextNode(str(value).encode('ascii', errors='ignore'))
                    node.appendChild(node_txt)
                    element.appendChild(node)
        return element

    def _get(self, url):
        """
        Handle HTTP GET's to the API
        """
        headers = {
            "Authorization": "Basic %s" % self._get_auth_string(),
            "User-Agent": "pyChargify",
            "Content-Type": 'text/xml'
        }

        r = httplib.HTTPSConnection(self.request_host)
        r.request('GET', url, None, headers)
        response = r.getresponse()

        # Unauthorized Error
        if response.status == 401:
            raise ChargifyUnAuthorized()

        # Forbidden Error
        elif response.status == 403:
            raise ChargifyForbidden()

        # Not Found Error
        elif response.status == 404:
            raise ChargifyNotFound()

        # Unprocessable Entity Error
        elif response.status == 422:
            raise ChargifyUnProcessableEntity()

        # Generic Server Errors
        elif response.status in [405, 500]:
            raise ChargifyServerError()

        return response.read()

    def _post(self, url, data):
        """
        Handle HTTP POST's to the API
        """
        return self._request('POST', url, data)

    def _put(self, url, data):
        """
        Handle HTTP PUT's to the API
        """
        return self._request('PUT', url, data)

    def _delete(self, url, data):
        """
        Handle HTTP DELETE's to the API
        """
        return self._request('DELETE', url, data)

    def _request(self, method, url, data=''):
        """
        Handled the request and sends it to the server
        """
        http = httplib.HTTPSConnection(self.request_host)

        http.putrequest(method, url)
        http.putheader("Authorization", "Basic %s" % self._get_auth_string())
        http.putheader("User-Agent", "pychargify")
        http.putheader("Host", self.request_host)
        http.putheader("Accept", "application/xml")
        http.putheader("Content-Length", str(len(data)))
        http.putheader("Content-Type", 'text/xml; charset="UTF-8"')
        http.endheaders()

        # print('sending: %s' % data)
        # print('url: %s' % url)
        # print('method: %s' % method)

        http.send(data)
        response = http.getresponse()

        # Unauthorized Error
        if response.status == 401:
            raise ChargifyUnAuthorized()

        # Forbidden Error
        elif response.status == 403:
            raise ChargifyForbidden()

        # Not Found Error
        elif response.status == 404:
            raise ChargifyNotFound()

        # Unprocessable Entity Error
        elif response.status == 422:

            error = ChargifyUnProcessableEntity()
            xml = response.read()
            if xml:
                dom = minidom.parseString(self.fix_xml_encoding(xml))
                error.errors = []
                for errorNodes in dom.childNodes:

                    for errorNode in errorNodes.childNodes:
                        error.errors.append(errorNode.firstChild.data)

            raise error

        # Generic Server Errors
        elif response.status in [405, 500]:
            raise ChargifyServerError()

        return response.read()

    def _save(self, url, node_name):
        """
        Save the object using the passed URL as the API end point
        """
        dom = minidom.Document()
        dom.appendChild(self._toxml(dom))

        request_made = {
            'day': datetime.datetime.today().day,
            'month': datetime.datetime.today().month,
            'year': datetime.datetime.today().year
        }

        if self.id:
            obj = self._applyS(self._put('/' + url + '/' + str(self.id) + '.xml',
                                         dom.toxml(encoding="utf-8")), self.__name__, node_name)
            if obj:
                if type(obj.updated_at) == datetime.datetime:
                    if (obj.updated_at.day == request_made['day']) and \
                            (obj.updated_at.month == request_made['month']) and \
                            (obj.updated_at.year == request_made['year']):
                        self.saved = True
                        return (True, obj)
            return (False, obj)
        else:
            obj = self._applyS(self._post('/' + url + '.xml',
                                          dom.toxml(encoding="utf-8")), self.__name__, node_name)
            if obj:
                if type(obj.updated_at) == datetime.datetime:
                    if (obj.updated_at.day == request_made['day']) and \
                            (obj.updated_at.month == request_made['month']) and \
                            (obj.updated_at.year == request_made['year']):
                        return (True, obj)
            return (False, obj)

    def _get_auth_string(self):
        return base64.encodestring('%s:%s' % (self.api_key, 'x'))[:-1]


class ChargifyCustomer(ChargifyBase):
    """
    Represents Chargify Customers
    @license    GNU General Public License
    """
    __name__ = 'ChargifyCustomer'
    __attribute_types__ = {}
    __xmlnodename__ = 'customer'

    id = None
    first_name = ''
    last_name = ''
    email = ''
    organization = ''
    reference = ''
    created_at = None
    modified_at = None

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyCustomer, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def getAll(self):
        return self._applyA(self._get('/customers.xml'),
                            self.__name__, 'customer')

    def filter(self, **kwargs):
        params = urllib.urlencode(kwargs)

        return self._applyA(self._get('/customers.xml?' + params),
                            self.__name__, 'customer')

    def getById(self, id):
        return self._applyS(self._get('/customers/' + str(id) + '.xml'),
                            self.__name__, 'customer')

    def getByReference(self, reference):
        return self._applyS(self._get('/customers/lookup.xml?reference=' +
                                      str(reference)), self.__name__, 'customer')

    def getSubscriptions(self):
        obj = ChargifySubscription(self.api_key, self.sub_domain)
        return obj.getByCustomerId(self.id)

    def save(self):
        return self._save('customers', 'customer')


class ChargifyProduct(ChargifyBase):
    """
    Represents Chargify Products
    @license    GNU General Public License
    """
    __name__ = 'ChargifyProduct'
    __attribute_types__ = {}
    __xmlnodename__ = 'product'

    id = None
    price_in_cents = 0
    name = ''
    handle = ''
    product_family = {}
    accounting_code = ''
    interval_unit = ''
    interval = 0

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyProduct, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def getAll(self):
        return self._applyA(self._get('/products.xml'),
                            self.__name__, 'product')

    def getById(self, id):
        return self._applyS(self._get('/products/' + str(id) + '.xml'),
                            self.__name__, 'product')

    def getByHandle(self, handle):
        return self._applyS(self._get('/products/handle/' + str(handle) +
                                      '.xml'), self.__name__, 'product')

    def save(self):
        return self._save('products', 'product')

    def getPaymentPageUrl(self):
        return ('https://' + self.request_host + '/h/' +
                self.id + '/subscriptions/new')

    def getPriceInDollars(self):
        return round(float(self.price_in_cents) / 100, 2)

    def getFormattedPrice(self):
        return "$%.2f" % (self.getPriceInDollars())


class Usage(object):
    def __init__(self, id, memo, quantity):
        self.id = id
        self.quantity = int(quantity)
        self.memo = memo


class ChargifySubscriptionComponent(ChargifyBase):
    """
    Represents Chargify Subscription components
    @license    GNU General Public License
    """
    __name__ = 'ChargifySubscription'
    __attribute_types__ = {
    }
    __xmlnodename__ = 'component'

    component_id = None
    enabled = False

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifySubscriptionComponent, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename


class ChargifySubscription(ChargifyBase):
    """
    Represents Chargify Subscriptions
    @license    GNU General Public License
    """
    __name__ = 'ChargifySubscription'
    __attribute_types__ = {
        'customer': 'ChargifyCustomer',
        'product': 'ChargifyProduct',
        'credit_card': 'ChargifyCreditCard',
        'components': "ChargifySubscriptionComponent"
    }
    __xmlnodename__ = 'subscription'

    id = None
    state = ''
    balance_in_cents = 0
    current_period_started_at = None
    current_period_ends_at = None
    trial_started_at = None
    trial_ended_attrial_ended_at = None
    activated_at = None
    expires_at = None
    created_at = None
    updated_at = None
    customer = None
    product = None
    product_handle = ''
    credit_card = None

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifySubscription, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def getAll(self):
        return self._applyA(self._get('/subscriptions.xml'),
                            self.__name__, 'subscription')

    def filter(self, **kwargs):
        params = urllib.urlencode(kwargs)

        return self._applyA(self._get('/subscriptions.xml?' + params),
                            self.__name__, 'subscription')

    def createUsage(self, component_id, quantity, memo=None):
        """
        Creates usage for the given component id.
        """

        data = '''<?xml version="1.0" encoding="UTF-8"?><usage>
            <quantity>%d</quantity><memo>%s</memo></usage>''' % (
            quantity, memo or "")

        dom = minidom.parseString(self.fix_xml_encoding(
            self._post('/subscriptions/%s/components/%d/usages.xml' % (
                str(self.id), component_id), data)))

        return [Usage(*tuple(chain.from_iterable([[x.data
                                                   for x in i.childNodes] or [None] for i in n.childNodes])))
                for n in dom.getElementsByTagName('usage')]

    def getByCustomerId(self, customer_id):
        return self._applyA(self._get('/customers/' + str(customer_id) +
                                      '/subscriptions.xml'), self.__name__, 'subscription')

    def getBySubscriptionId(self, subscription_id):
        # Throws error if more than element is returned
        i, = self._applyA(self._get('/subscriptions/' + str(subscription_id) +
                                    '.xml'), self.__name__, 'subscription')
        return i

    def save(self):
        return self._save('subscriptions', 'subscription')

    def resetBalance(self):
        self._put("/subscriptions/" + str(self.id) + "/reset_balance.xml", "")

    def purge(self):
        self._post("/subscriptions/" + str(self.id) + "/purge.xml?ack=" + str(self.customer.id), "")

    def getTransactions(self):
        obj = ChargifyTransaction(self.api_key, self.sub_domain)
        return obj.getByCustomerId(self.id)

    def reactivate(self):
        self._put("/subscriptions/" + str(self.id) + "/reactivate.xml", "")

    def upgrade(self, toProductHandle):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
  <subscription>
    <product_handle>%s</product_handle>
  </subscription>""" % (toProductHandle)
        # end improper indentation

        return self._applyS(self._put("/subscriptions/" + str(self.id) + ".xml",
                                      xml), self.__name__, "subscription")

    def remove_delayed_cancel(self):
        xml = """"""

        return self._delete("/subscriptions/" + str(self.id) + "/delayed_cancel.xml", xml)

    def delayed_cancel(self, message):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<subscription>
  <cancel_at_end_of_period>1</cancel_at_end_of_period>
  <cancellation_message>
    %s
  </cancellation_message>
</subscription>""" % (message)

        return self._put("/subscriptions/" + str(self.id) + ".xml", xml)

    def cancel(self, message):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<subscription>
  <cancellation_message>
    %s
  </cancellation_message>
</subscription>""" % (message)

        return self._applyS(self._delete("/subscriptions/" + str(self.id) + ".xml", xml), self.__name__, "subscription")

    def delayed_product_change(self, product_handle):
        """
        This method schedules the product change to happen automatically at the 
        subscription’s next renewal date. 
        
        @param product_handle: the new product
        """

        xml = """<?xml version="1.0" encoding="UTF-8"?>
<subscription>
  <product_handle>%s</product_handle>
  <product_change_delayed>true</product_change_delayed>
</subscription>""" % (product_handle)

        xml = self._put("/subscriptions/" + str(self.id) + ".xml", xml)
        print
        xml
        return None

    def unsubscribe(self, message):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<subscription>
  <cancellation_message>
    %s
  </cancellation_message>
</subscription>""" % (message)

        self._delete("/subscriptions/" + str(self.id) + ".xml", xml)

    def preview_migrate(self, product_id):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<migration>
  <product_id>%s</product_id>
</migration>""" % (product_id)
        # end improper indentation

        return self._applyS(self._post("/subscriptions/" + str(self.id) + "/migrations/preview.xml",
                                       xml), "ChargifyMigration", "migration")

    def migrate(self, product_id):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<migration>
  <product_id>%s</product_id>
</migration>""" % (product_id)
        # end improper indentation

        return self._applyS(self._post("/subscriptions/" + str(self.id) + "/migrations.xml",
                                       xml), "ChargifySubscription", "subscription")


class ChargifyComponent(ChargifyBase):
    """
    Represents Chargify Components
    @license    GNU General Public License
    """
    __name__ = 'ChargifyComponent'
    __attribute_types__ = {
        'price': 'ChargifyPrice'
    }
    __xmlnodename__ = 'component'

    allocated_quantity = None

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyComponent, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def get_all_by_subscription_id(self, subscription_id):
        return self._applyA(self._get('/subscriptions/' + str(subscription_id) +
                                      '/components.xml'), self.__name__, 'component')

    def get_all_by_product_family(self, product_family_id):
        return self._applyA(self._get('/product_families/' + str(product_family_id) +
                                      '/components.xml'), self.__name__, 'component')

    def allocate(self, subscription_id, component_id, quantity):
        """
        This method allocates quantities for a given component.

        @param subscription_id: The subscription id
        @param component_id: The component id to allocate
        @param quantity: Integer quantity, use  1 or 0 for On/Off components

        """
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<allocation>
  <quantity>%s</quantity>
</allocation>""" % (quantity)

        return self._applyS(self._post(
            "/subscriptions/" + str(subscription_id) + "/components/" + str(component_id) + "/allocations.xml", xml),
            "ChargifyComponent", "component")

    def get_by_component_id(self, subscription_id, component_id):
        return self._applyA(self._get("/subscriptions/" + str(subscription_id) + '/components/' + str(component_id) +
                                      ".xml"), self.__name__, 'component')


class ChargifyPrice(ChargifyBase):
    __name__ = 'ChargifyPrice'
    __attribute_types__ = {}
    __xmlnodename__ = 'price'

    id = None
    component_id = None
    starting_quantity = ''
    ending_quantity = ''
    unit_price = ''
    price_point_id = None
    formatted_unit_price = ''

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyPrice, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename


class ChargifyPricePoint(ChargifyBase):
    __name__ = 'ChargifyPricePoint'
    __attribute_types__ = {
        'price': 'ChargifyPrice'
    }
    __xmlnodename__ = 'price_point'

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyPricePoint, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def get_by_component_id(self, component_id):
        return self._applyA(
            self._get("/components/" + str(component_id) + "/price_points.xml"),
            self.__name__,
            "price_point"
        )


class ChargifyTransaction(ChargifyBase):
    __name__ = 'ChargifyTransaction'
    __attribute_types__ = {}
    __single_value_attribute_types__ = {
        "id": int,
        "amount_in_cents": int,
        "starting_balance_in_cents": int,
        "ending_balance_in_cents": int,
        "subscription_id": int
    }
    __xmlnodename__ = 'transaction'

    transaction_type = None
    id = None
    amount_in_cents = None
    created_at = None
    starting_balance_in_cents = None
    ending_balance_in_cents = None
    memo = None
    subscription_id = None
    product_id = None
    success = None
    payment_id = None
    kind = None
    gateway_transaction_id = None
    gateway_order_id = None

    def getByCustomerId(self, customer_id):
        return self._applyA(self._get('/subscriptions/' + str(customer_id) +
                                      '/transactions.xml'), self.__name__, 'transaction')


class ChargifyMigration(ChargifyBase):
    __name__ = 'ChargifyMigration'
    __attribute_types__ = {}
    __single_value_attribute_types__ = {
        "prorated_adjustment_in_cents": int,
        "charge_in_cents": int,
        "payment_due_in_cents": int,
        "credit_applied_in_cents": int
    }
    __xmlnodename__ = 'migration'

    prorated_adjustment_in_cents = None
    charge_in_cents = None
    payment_due_in_cents = None
    credit_applied_in_cents = None


class ChargifyCreditCard(ChargifyBase):
    """
    Represents Chargify Credit Cards
    """
    __name__ = 'ChargifyCreditCard'
    __attribute_types__ = {}
    __xmlnodename__ = 'credit_card_attributes'

    first_name = ''
    last_name = ''
    full_number = ''
    masked_card_number = ''
    expiration_month = ''
    expiration_year = ''
    cvv = ''
    type = ''
    billing_address = ''
    billing_city = ''
    billing_state = ''
    billing_zip = ''
    billing_country = ''
    zip = ''

    def __init__(self, apikey, subdomain, nodename=''):
        super(ChargifyCreditCard, self).__init__(apikey, subdomain)
        if nodename:
            self.__xmlnodename__ = nodename

    def save(self, subscription):
        path = "/subscriptions/%s.xml" % (subscription.id)

        data = u"""<?xml version="1.0" encoding="UTF-8"?>
  <subscription>
    <credit_card_attributes>
      <full_number>%s</full_number>
      <expiration_month>%s</expiration_month>
      <expiration_year>%s</expiration_year>
      <cvv>%s</cvv>
      <first_name>%s</first_name>
      <last_name>%s</last_name>
      <zip>%s</zip>
    </credit_card_attributes>
  </subscription>""" % (self.full_number, self.expiration_month,
                        self.expiration_year, self.cvv, self.first_name,
                        self.last_name, self.zip)
        # end improper indentation

        return self._applyS(self._put(path, data),
                            self.__name__, "subscription")


class ChargifyPostBack(ChargifyBase):
    """
    Represents Chargify API Post Backs
    @license    GNU General Public License
    """
    subscriptions = []

    def __init__(self, apikey, subdomain, postback_data):
        ChargifyBase.__init__(apikey, subdomain)
        if postback_data:
            self._process_postback_data(postback_data)

    def _process_postback_data(self, data):
        """
        Process the Json array and fetches the Subscription Objects
        """
        csub = ChargifySubscription(self.api_key, self.sub_domain)
        postdata_objects = json.loads(data)
        for obj in postdata_objects:
            self.subscriptions.append(csub.getBySubscriptionId(obj))


class Chargify:
    """
    The Chargify class provides the main entry point to the Chargify API
    @license    GNU General Public License
    """
    api_key = ''
    sub_domain = ''

    def __init__(self, apikey=None, subdomain=None, cred_file=None):
        ''' We take either an api_key and sub_domain, or a path
        to a file with JSON that defines those two, or we throw
        an error.'''

        if self.api_key and self.sub_domain:
            self.api_key = apikey
            self.sub_domain = subdomain
            return
        elif cred_file:
            f = open(cred_file)
            credentials = json.loads(f.read())
            self.api_key = credentials['api_key']
            self.sub_domain = credentials['sub_domain']
            return
        else:
            print
            "Need either an api_key and subdomain, or credential file. Exiting."
            exit()

    def Customer(self, nodename=''):
        return ChargifyCustomer(self.api_key, self.sub_domain, nodename)

    def Product(self, nodename=''):
        return ChargifyProduct(self.api_key, self.sub_domain, nodename)

    def Subscription(self, nodename=''):
        return ChargifySubscription(self.api_key, self.sub_domain, nodename)

    def SubscriptionComponent(self, nodename=''):
        return ChargifySubscriptionComponent(self.api_key, self.sub_domain, nodename)

    def Component(self, nodename=''):
        return ChargifyComponent(self.api_key, self.sub_domain, nodename)

    def PricePoint(self, nodename=''):
        return ChargifyPricePoint(self.api_key, self.sub_domain, nodename)

    def CreditCard(self, nodename=''):
        return ChargifyCreditCard(self.api_key, self.sub_domain, nodename)

    def PostBack(self, postbackdata):
        return ChargifyPostBack(self.api_key, self.sub_domain, postbackdata)
