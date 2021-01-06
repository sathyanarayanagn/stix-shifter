from stix_shifter_utils.stix_translation.src.json_to_stix import json_to_stix_translator
from stix_shifter_utils.stix_translation.src.utils import transformers
from stix_shifter_modules.mcafee_epo_events.entry_point import EntryPoint
from stix_shifter.stix_translation import stix_translation
import json
import base64
import logging
from stix_shifter_utils.stix_translation.src.utils.transformer_utils import get_module_transformers

MODULE = "mcafee_epo_events"
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()

entry_point = EntryPoint()
map_data = entry_point.get_results_translator().map_data
data_source = {
    "type": "identity",
    "id": "identity--3532c56d-ea72-48be-a2ad-1a53f4c9c6d3",
    "name": "McafeeEPO",
    "identity_class": "events"
}
map_data_mc = {
            'EPOEvents.DetectedUTC': {'key': 'first_observed', 'transformer': 'McAfeeToTimestamp', 'cybox': False},
            'EPOEvents.ReceivedUTC': {'key': 'last_observed', 'transformer': 'McAfeeToTimestamp', 'cybox': False},
            'EPOEvents.AnalyzerName': {'key': 'x_com_mcafee_epo.analyzer_name', 'cybox': False},
            'EPOEvents.AnalyzerVersion': {'key': 'x_com_mcafee_epo.analyzer_version', 'cybox': False},
            'EPOEvents.AnalyzerHostName': {'key': 'x_com_mcafee_epo.analyzer_hostname', 'cybox': False},
            'EPOEvents.AnalyzerDetectionMethod': {'key': 'x_com_mcafee_epo.analyzer_detection_method', 'cybox': False},
            'EPOEvents.SourceHostName': {'key': 'x_com_mcafee_epo.source_hostname', 'cybox': False},
            'EPOEvents.TargetHostName': {'key': 'x_com_mcafee_epo.target_hostname', 'cybox': False},
            'EPOEvents.TargetMAC': [{'key': 'mac-addr.value', 'object': 'dst_mac'},
                                    {'key': 'ipv4-addr.resolves_to_refs', 'object': 'dst_ip',
                                     'references': ['dst_mac']},
                                    {'key': 'ipv6-addr.resolves_to_refs', 'object': 'dst_ip',
                                     'references': ['dst_mac']}],
            'EPOEvents.TargetUserName': {'key': 'x_com_mcafee_epo.target_username', 'cybox': False},
            'EPOEvents.SourceUserName': {'key': 'x_com_mcafee_epo.source_username', 'cybox': False},
            'EPOEvents.ThreatCategory': {'key': 'x_com_mcafee_epo.threat_category', 'cybox': False},
            'EPOEvents.ThreatSeverity': {'key': 'x_com_mcafee_epo.threat_severity', 'cybox': False},
            'EPOEvents.ThreatName': {'key': 'x_com_mcafee_epo.threat_name', 'cybox': False},
            'EPOEvents.ThreatType': {'key': 'x_com_mcafee_epo.threat_type', 'cybox': False},
            'EPOEvents.ThreatActionTaken': {'key': 'x_com_mcafee_epo.threat_action_taken', 'cybox': False},
            'EPOEvents.ThreatHandled': {'key': 'x_com_mcafee_epo.threat_handled', 'cybox': False},
            'EPOEvents.ThreatEventID': {'key': 'x_com_mcafee_epo.threat_id', 'cybox': False},
            'EPOEvents.SourceIPV4': [{'key': 'ipv4-addr.value', 'object': 'src_ip', 'transformer': 'McAfeeToIPv4'},
                                     {'key': 'network-traffic.src_ref', 'object': 'nt', 'references': 'src_ip'}],
            'EPOEvents.TargetIPV4': [{'key': 'ipv4-addr.value', 'object': 'dst_ip', 'transformer': 'McAfeeToIPv4'},
                                     {'key': 'network-traffic.dst_ref', 'object': 'nt', 'references': 'dst_ip'}],
            'EPOEvents.SourceIPV6': [{'key': 'ipv6-addr.value', 'object': 'src_ip'},
                                     {'key': 'network-traffic.src_ref', 'object': 'nt', 'references': 'src_ip'}],
            'EPOEvents.TargetIPV6': [{'key': 'ipv6-addr.value', 'object': 'dst_ip'},
                                     {'key': 'network-traffic.dst_ref', 'object': 'nt', 'references': 'dst_ip'}],
            'EPOEvents.TargetFileName': [
                {'key': 'directory.path', 'object': 'directory', 'transformer': 'ToDirectoryPath'},
                {'key': 'file.name', 'object': 'filename', 'transformer': 'ToFileName'},
                {'key': 'file.parent_directory_ref', 'object': 'filename', 'references': 'directory'}],
            'EPOEvents.TargetPort': {'key': 'network-traffic.dst_port', 'object': 'nt'},
            'EPOEvents.TargetProtocol': {'key': 'network-traffic.protocols', 'object': 'nt',
                                         'transformer': 'FormatMcafeeProtocol'},
            'EPOEvents.SourceURL': {'key': 'url.value'},
            'EPOEvents.TargetProcessName': {'key': 'process.name', 'object': 'dst_process'},
            'EPOEvents.SourceProcessName': {'key': 'process.name', 'object': 'src_process'},
            'EPOEvents.SourceMAC': [{'key': 'mac-addr.value', 'object': 'src_mac'},
                                    {'key': 'ipv4-addr.resolves_to_refs', 'object': 'src_ip',
                                     'references': ['src_mac']},
                                    {'key': 'ipv6-addr.resolves_to_refs', 'object': 'src_ip',
                                     'references': ['src_mac']}]}
data = {'EPOEvents.ServerID': 'CLDBGDEVMGT0321', 'EPOEvents.ReceivedUTC': '2019-12-13T12:09:21+05:30',
                 'EPOEvents.DetectedUTC': '2019-12-13T12:08:39+05:30',
                 'EPOEvents.EventTimeLocal': '2019-12-13T12:08:39+5:30',
                 'EPOEvents.AgentGUID': '37C7FA52-1D6E-11EA-04ED-005056AF5265', 'EPOEvents.Analyzer': 'ENDP_AM_1060',
                 'EPOEvents.AnalyzerName': 'McAfeeEndpointSecurity', 'EPOEvents.AnalyzerVersion': '10.6.0',
                 'EPOEvents.AnalyzerHostName': 'CLDBGDEVMGT0330', 'EPOEvents.AnalyzerIPV6': '0:0:0:0:0:FFFF:AFE:2518',
                 'EPOEvents.AnalyzerMAC': '005056af5265', 'EPOEvents.AnalyzerDATVersion': '3920.0',
                 'EPOEvents.AnalyzerEngineVersion': '6010.8670', 'EPOEvents.SourceHostName': 'CLDBGDEVMGT0330',
                 'EPOEvents.SourceIPV4': -1963055655, 'EPOEvents.SourceIPV6': '0:0:0:0:0:FFFF:AFE:2518',
                 'EPOEvents.SourceMAC': '30-65-EC-6F-C4-58', 'EPOEvents.SourceUserName': 'sample',
                 'EPOEvents.SourceProcessName': 'C:\\ProgramFiles(x86)\\MozillaFirefox\\firefox.exe',
                 'EPOEvents.SourceURL': 'www.sample.com', 'EPOEvents.TargetHostName': 'CLDBGDEVMGT0330',
                 'EPOEvents.TargetIPV4': -196305655, 'EPOEvents.TargetIPV6': '0:0:0:0:0:FFFF:AFE:2518',
                 'EPOEvents.TargetMAC': '30-63-EC-6F-C4-34', 'EPOEvents.TargetUserName': 'CLDBGDEVMGT0330\\cloudadmin',
                 'EPOEvents.TargetPort': 21, 'EPOEvents.TargetProtocol': 'tcp', 'EPOEvents.TargetProcessName': None,
                 'EPOEvents.TargetFileName': 'C:\\Users\\cloudadmin\\AppData\\Local\\Temp\\2FHdTp7V.txt.part',
                 'EPOEvents.ThreatCategory': 'av.detect', 'EPOEvents.ThreatEventID': 1278,
                 'EPOEvents.ThreatSeverity': 2, 'EPOEvents.ThreatName': 'EICARtestfile', 'EPOEvents.ThreatType': 'test',
                 'EPOEvents.ThreatActionTaken': 'IDS_ALERT_ACT_TAK_DEL', 'EPOEvents.ThreatHandled': True,
                 'EPOEvents.AnalyzerDetectionMethod': 'On-AccessScan'}
options = {}


class TestTransform(object):
    @staticmethod
    def get_first(itr, constraint):
        return next(
            (obj for obj in itr if constraint(obj)),
            None
        )

    @staticmethod
    def get_first_of_type(itr, typ):
        return TestTransform.get_first(itr, lambda o: type(o) == dict and o.get('type') == typ)

    @staticmethod
    def get_object_keys(objects):
        for k, v in objects.items():
            if k == 'type':
                yield v
            elif isinstance(v, dict):
                for id_val in TestTransform.get_object_keys(v):
                    yield id_val

    def test_common_prop(self):

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)

        assert (result_bundle['type'] == 'bundle')
        result_bundle_objects = result_bundle['objects']

        result_bundle_identity = result_bundle_objects[0]
        assert (result_bundle_identity['type'] == data_source['type'])
        assert (result_bundle_identity['id'] == data_source['id'])
        assert (result_bundle_identity['name'] == data_source['name'])
        assert (result_bundle_identity['identity_class']
                == data_source['identity_class'])

        observed_data = result_bundle_objects[1]

        assert (observed_data['id'] is not None)
        assert (observed_data['type'] == "observed-data")
        assert (observed_data['created_by_ref'] == result_bundle_identity['id'])

        # assert(observed_data['number_observed'] == 5)
        assert (observed_data['created'] is not None)
        assert (observed_data['modified'] is not None)


    def test_common_prop1(self):

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)

        assert (result_bundle['type'] == 'bundle')
        result_bundle_objects = result_bundle['objects']

        result_bundle_identity = result_bundle_objects[0]
        assert (result_bundle_identity['type'] == data_source['type'])
        assert (result_bundle_identity['id'] == data_source['id'])
        assert (result_bundle_identity['name'] == data_source['name'])
        assert (result_bundle_identity['identity_class']
                == data_source['identity_class'])

        observed_data = result_bundle_objects[1]

        assert (observed_data['id'] is not None)
        assert (observed_data['type'] == "observed-data")
        assert (observed_data['created_by_ref'] == result_bundle_identity['id'])

        assert (observed_data['number_observed'] == 1)
        assert (observed_data['created'] is not None)
        assert (observed_data['modified'] is not None)
        assert (observed_data['first_observed'] is not None)
        assert (observed_data['last_observed'] is not None)

    def test_cybox_observables(self):

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)


        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']

        nt_object = TestTransform.get_first_of_type(objects.values(), 'network-traffic')
        assert (nt_object.keys() ==
                {'type', 'src_ref', 'dst_ref', 'dst_port', 'protocols'})

        assert (nt_object['dst_port'] == 21)
        assert (nt_object['protocols'] == ['tcp'])



        ip_ref = nt_object['dst_ref']
        assert (ip_ref in objects), "dst_ref with key {nt_object['dst_ref']} not found"
        ip_obj = objects[ip_ref]


        assert (ip_obj.keys() == {'type', 'value', 'resolves_to_refs'})
        assert (ip_obj['type'] == 'ipv4-addr')
        assert (ip_obj['value'] == '116.76.157.9')

        ip_ref = nt_object['src_ref']
        assert (ip_ref in objects), "src_ref with key {nt_object['src_ref']} not found"
        ip_obj = objects[ip_ref]
        assert (ip_obj.keys() == {'type', 'value', 'resolves_to_refs'})
        assert (ip_obj['type'] == 'ipv4-addr')
        assert (ip_obj['value'] == '10.254.37.217')

        curr_obj = TestTransform.get_first_of_type(objects.values(), 'url')
        assert (curr_obj is not None), 'url object type not found'
        assert (curr_obj.keys() == {'type', 'value'})
        assert (curr_obj['value'] == 'www.sample.com')


        curr_obj = TestTransform.get_first_of_type(objects.values(), 'file')
        assert (curr_obj is not None), 'file object type not found'
        assert (curr_obj.keys() == {'type', 'name', 'parent_directory_ref'})

        assert (nt_object['dst_port'] is not None)
        assert (nt_object['protocols'] is not None)
        assert (ip_obj['type'] is not None)
        assert (ip_obj['value'] is not None)


    def test_custom_props(self):

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)
        observed_data = result_bundle['objects'][1]

        assert ('x_com_mcafee_epo' in observed_data)
        custom_props = observed_data['x_com_mcafee_epo']
        assert (custom_props['analyzer_name'] == data['EPOEvents.AnalyzerName'])
        assert (custom_props['analyzer_version'] == data['EPOEvents.AnalyzerVersion'])
        assert (custom_props['analyzer_hostname'] == data['EPOEvents.AnalyzerHostName'])
        assert (custom_props['source_hostname'] == data['EPOEvents.SourceHostName'])
        assert (custom_props['analyzer_detection_method'] == data['EPOEvents.AnalyzerDetectionMethod'])
        assert (custom_props['target_hostname'] == data['EPOEvents.TargetHostName'])
        assert (custom_props['target_username'] == data['EPOEvents.TargetUserName'])
        assert (custom_props['source_username'] == data['EPOEvents.SourceUserName'])
        assert (custom_props['threat_category'] == data['EPOEvents.ThreatCategory'])
        assert (custom_props['threat_severity'] == data['EPOEvents.ThreatSeverity'])
        assert (custom_props['threat_name'] == data['EPOEvents.ThreatName'])
        assert (custom_props['threat_type'] == data['EPOEvents.ThreatType'])
        assert (custom_props['threat_action_taken'] == data['EPOEvents.ThreatActionTaken'])
        assert (custom_props['threat_handled'] == data['EPOEvents.ThreatHandled'])
        assert (custom_props['threat_id'] == data['EPOEvents.ThreatEventID'])


        assert custom_props['threat_id'] is not None
        assert custom_props['threat_handled'] is not None
        assert custom_props['threat_action_taken'] is not None
        assert custom_props['threat_type'] is not None
        assert custom_props['threat_name'] is not None
        assert custom_props['threat_severity'] is not None
        assert custom_props['threat_category'] is not None
        assert custom_props['source_username'] is not None
        assert custom_props['target_username'] is not None
        assert custom_props['target_hostname'] is not None
        assert custom_props['source_hostname'] is not None
        assert custom_props['analyzer_hostname'] is not None



    def test_custom_mapping(self):

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)

        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']

        nt_object = TestTransform.get_first_of_type(objects.values(), 'network-traffic')
        # assert (nt_object is not None), 'network-traffic object type not found'

        assert ('x_com_mcafee_epo' in observed_data)
        custom_props = observed_data['x_com_mcafee_epo']

        assert (custom_props['analyzer_name'] == 'McAfeeEndpointSecurity')
        assert (custom_props['analyzer_version'] == '10.6.0')
        assert (custom_props['analyzer_hostname'] == 'CLDBGDEVMGT0330')
        assert (custom_props['analyzer_detection_method'] == 'On-AccessScan')
        assert (custom_props['source_hostname'] == 'CLDBGDEVMGT0330')
        assert (custom_props['target_hostname'] == 'CLDBGDEVMGT0330')
        assert (custom_props['target_username'] == 'CLDBGDEVMGT0330\\cloudadmin')
        assert (custom_props['source_username'] == 'sample')
        assert (custom_props['threat_category'] == 'av.detect')
        assert (custom_props['threat_severity'] == 2)
        assert (custom_props['threat_name'] == 'EICARtestfile')
        assert (custom_props['threat_type'] == 'test')
        assert (custom_props['threat_action_taken'] == 'IDS_ALERT_ACT_TAK_DEL')
        assert (custom_props['threat_handled'] == True)
        assert (custom_props['threat_id'] == 1278)

    def test_none_empty_values_in_results(self):
        url = None
        source_ip = "fd80:655e:171d:30d4:fd80:655e:171d:30d4"
        destination_ip = "255.255.255.1"
        file_name = ""
        source_mac = "00-00-5E-00-53-00"
        destination_mac = "00-00-5A-00-55-01"
        data = {"sourceip": source_ip, "destinationip": destination_ip, "url": url,
                 "protocol": 'TCP',
                 "destinationport": 2000, "filename": file_name,
                "sourcemac": source_mac, "destinationmac": destination_mac}

        result_bundle = json_to_stix_translator.convert_to_stix(
            data_source, map_data, [data], get_module_transformers(MODULE), options)

        assert (result_bundle['type'] == 'bundle')

        result_bundle_objects = result_bundle['objects']
        observed_data = result_bundle_objects[1]

        assert ('objects' in observed_data)
        objects = observed_data['objects']

        obj_keys = []
        for key in TestTransform.get_object_keys(objects):
            obj_keys.append(key)

        # url object has None in results so url object will be skipped while creating the observables
        assert ('url' not in obj_keys)
        # file object has empty string in results so file object will be skipped while creating the observables
        assert ('file' not in obj_keys)