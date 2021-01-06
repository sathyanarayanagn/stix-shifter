import base64
import json
import re
from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient
from stix_shifter_utils.utils.error_response import ErrorResponder


class APIClient():
    PING_ENDPOINT = 'core.get-status'

    def __init__(self, connection, configuration):
        self.client = "data source API client"
        self.output_mode = 'json'
        self.endpoint_start = 'remote/'
        self.authenticated = False
        self.headers = dict()
        # proxy = connection.get('proxy')
        #
        # if proxy is None:
        #     proxy_url = proxy.get('url')
        #     self.headers['proxy'] = 'https://webgateway.itm.mcafee.com:9090'
        #
        # if proxy is not None and proxy.get('auth') is not None:
        #     proxy_auth = proxy.get('auth')
        #     self.headers['proxy'] = 'https://' + proxy.auth
        #     self.headers['proxy-authorization'] = 'Basic ' + proxy_auth

        auth = configuration.get('auth')
        self.headers['Authorization'] = b"Basic " + base64.b64encode(
            (auth['username'] + ':' + auth['password']).encode('ascii'))
        # headers = dict()
        # auth = configuration.get('auth')
        # headers['Authorization'] = b"Basic " + base64.b64encode(
        #     (auth['username'] + ':' + auth['password']).encode('ascii'))
        # headers = headers['Authorization']
        self.client = RestApiClient(connection.get('host'),
                                    connection.get('port'),
                                    self.headers,
                                    cert_verify=connection.get('cert_verify', False)
                                    )
        try:
            response = self.ping_box();
            if response.code == 200:
                print('success')
            else:
                print('unable to connect to data source')
        except Exception as err:
            print('error connecting to data source: {}')

    def ping_box(self):
        endpoint = self.endpoint_start + self.PING_ENDPOINT
        return self.client.call_api(endpoint, 'GET',self.headers)

    def create_search(self, query_expression):
        # Queries the data source
        return_obj = {}
        response = self.client.call_api("remote/core.executeQuery?target=EPOEvents&:output=json&" + query_expression,
                                        'GET')
        return self._handle_errors(response, return_obj)

    def create_query_connection(self, query):
        try:
            response = self.api_client.create_search(query)
            return response
        except Exception as err:
            print('error when creating search: {}'.format(err))
            raise

    def run_search(self, query_expression, offset=None, length=None):
        # Return the search results. Results must be in JSON format before being translated into STIX
        return {"code": 200, "search_id": query_expression, "results": "Results from search"}

    def _handle_errors(self, response, return_obj):
        response_code = response.code
        response_txt = response.read().decode('utf-8')

        if 200 <= response_code < 300:
            return_obj['success'] = True
            if response_txt:
                parsed_result = re.search("(?<=\[).+?(?=\])", response_txt).group(0)
        elif ErrorResponder.is_plain_string(response_txt):
            ErrorResponder.fill_error(return_obj, message=response_txt)
        elif ErrorResponder.is_json_string(response_txt):
            response_json = json.loads(response_txt)
            ErrorResponder.fill_error(return_obj, response_json, ['reason'])
        else:
            from stix_shifter.stix_transmission.src.modules.stix_bundle.stix_bundle_connector import \
                UnexpectedResponseException
            raise UnexpectedResponseException
        return parsed_result
