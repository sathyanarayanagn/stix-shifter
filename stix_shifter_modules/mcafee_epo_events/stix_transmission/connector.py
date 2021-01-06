import re

from stix_shifter_utils.modules.base.stix_transmission.base_sync_connector import BaseSyncConnector
from stix_shifter_utils.utils.error_response import ErrorResponder
from .api_client import APIClient
import json


class UnexpectedResponseException(Exception):
    pass


class Connector(BaseSyncConnector):
    def delete_query_connection(self, search_id):
        pass

    def __init__(self, connection, configuration):
        self.api_client = APIClient(connection, configuration)

    def _handle_ping_errors(self, response, return_obj):
        response_code = response.code

        if 200 <= response_code < 300:
            return_obj['success'] = True
            response_json = 'Connection Successful'
            if 'results' in response_json:
                return_obj['data'] = response_json
        else:
            return_obj['success'] = False
            response_json = 'Unable to Connect to Data Source'
            if 'results' in response_json:
                return_obj['data'] = response_json
        return return_obj

    def ping_connection(self):
        return_obj = {}
        try:
            response = self.api_client.ping_box()
            return self._handle_ping_errors(response, return_obj)
        except Exception as err:
            print('error when pinging datasource {}:'.format(err))
            raise

    def create_query_connection(self, query):
        try:
            response = self.api_client.create_search(query)
            return response
        except Exception as err:
            print('error when creating search: {}'.format(err))
            raise

    # Query is sent to data source and results are returned in one step
    def create_results_connection(self, search_id, offset, length):
        response_txt = None
        return_obj = {}
        try:
            query = search_id
            response = self.api_client.run_search(query, offset, length)
            return self._handle_errors(response, return_obj)

        except Exception as e:
            if response_txt is not None:
                ErrorResponder.fill_error(return_obj, message='unexpected exception')
                print('can not parse response: ' + str(response_txt))
            else:
                raise e

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

