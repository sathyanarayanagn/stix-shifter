from stix_shifter_modules.mcafee_epo_events.entry_point import EntryPoint
from stix_shifter_utils.modules.base.stix_transmission.base_status_connector import Status
from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient
from stix_shifter.stix_transmission import stix_transmission
from unittest.mock import patch
import unittest
from stix_shifter_modules.mcafee_epo_events.stix_transmission.api_client import APIClient

connection = {"host": "10.254.41.73", "port": 8443}
config = {"auth": {"username": "admin", "password": "1"}}




class TestMcafeeePOConnection(unittest.TestCase):
        @staticmethod
        @patch('stix_shifter_modules.mcafee_epo_events.stix_transmission.api_client')


        def test_ping_endpoint_good_return(self):



            transmission = stix_transmission.StixTransmission('mcafee_epo_events', connection ,config)
            ping_response = transmission.ping()

            assert ping_response is not None
            assert 'success' in ping_response
            assert ping_response['success']



        def test_query_response_found(self):



            query ="target=EPOEvents&where=(eq EPOEvents.SourceURL  \"www.sathya.com\")"
            transmission = stix_transmission.StixTransmission('mcafee_epo_events', connection , config)
            query_response = transmission.query(query)
            res = '{ "EPOEvents.ServerID" : "CLDBGQAEO0602", "EPOEvents.ReceivedUTC" : "2020-05-05T19:34:56+05:30", "EPOEvents.DetectedUTC" : "2019-08-26T12:14:32+05:30", "EPOEvents.EventTimeLocal" : "2019-08-26T12:14:32+05:30", "EPOEvents.AgentGUID" : "BDF820FE-C592-11E9-0E7D-005056AF0BDC", "EPOEvents.Analyzer" : "ENDP_FW_1060", "EPOEvents.AnalyzerName" : "McAfee Endpoint Security", "EPOEvents.AnalyzerVersion" : "10.6.1", "EPOEvents.AnalyzerHostName" : "CLDBGQAMGT1747", "EPOEvents.AnalyzerIPV4" : -1963057021, "EPOEvents.AnalyzerIPV6" : "0:0:0:0:0:FFFF:AFE:2083", "EPOEvents.AnalyzerMAC" : "005056af0bdc", "EPOEvents.AnalyzerDATVersion" : null, "EPOEvents.AnalyzerEngineVersion" : null, "EPOEvents.SourceHostName" : null, "EPOEvents.SourceIPV4" : -1963057021, "EPOEvents.SourceIPV6" : "0:0:0:0:0:FFFF:AFE:2083", "EPOEvents.SourceMAC" : null, "EPOEvents.SourceUserName" : "CLDBGQAMGT1747\\cloudadmin", "EPOEvents.SourceProcessName" : "ftp.exe", "EPOEvents.SourceURL" : "www.sathya.com", "EPOEvents.TargetHostName" : null, "EPOEvents.TargetIPV4" : 1084807085, "EPOEvents.TargetIPV6" : "0:0:0:0:0:FFFF:C0A8:D7AD", "EPOEvents.TargetMAC" : null, "EPOEvents.TargetUserName" : "CLDBGQAMGT1747\\cloudadmin", "EPOEvents.TargetPort" : 21, "EPOEvents.TargetProtocol" : "TCP", "EPOEvents.TargetProcessName" : null, "EPOEvents.TargetFileName" : "sathya", "EPOEvents.ThreatCategory" : "fw.intrusion", "EPOEvents.ThreatEventID" : 35001, "EPOEvents.ThreatSeverity" : 2, "EPOEvents.ThreatName" : "FTP_Block", "EPOEvents.ThreatType" : "IDS_FW_THREAT_TYPE_INTRUSION", "EPOEvents.ThreatActionTaken" : "blocked", "EPOEvents.ThreatHandled" : true, "EPOEvents.AnalyzerDetectionMethod" : "Firewall" }'

            assert query_response is not None
            assert query_response in res

