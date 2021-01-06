from stix_shifter.stix_translation import stix_translation
import unittest
import json

translation = stix_translation.StixTranslation()


def _remove_timestamp_from_query(queries):
    if isinstance(queries, list):
        query_list = []
        for query in queries:
            query_dict = json.loads(query)
            query_dict.pop("startTime")
            query_dict.pop("endTime")
            query_list.append(query_dict)
        return query_list


class TestQueryTranlator(unittest.TestCase):
    """
    class to perform unit test case McAfee epo connector translate query
    """

    def _test_query_assertions(self, query, queries):
        """
        to assert the each query in the list against expected result
        """
        self.assertIsInstance(query, dict)
        self.assertIsInstance(query['queries'], list)
        for each_query in query.get('queries'):
            self.assertIn(each_query, queries)

    def test_comp_exp(self):
        """
        Test with Equal operator
        """
        stix_pattern ="[ipv4-addr:value = '00.00.00.00'] START t'2019-01-28T12:24:01.009Z' STOP t'2019-01-28T12:54:01.009Z'"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2019-01-28 12:54:01.009")) ']

        self._test_query_assertions(query, queries)





    def test_comp_exp_without_qualifier(self):
        """
        Test with Equal operator with out qualifier
        """
        stix_pattern = "[ipv4-addr:value = '00.00.00.00']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))']


        self._test_query_assertions(query, queries)


    def test_comp_exp_using_OR(self):
        """
        Test with OR operator
        """
        stix_pattern = "[process:name = 'cmd.exe']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(or(eq EPOEvents.SourceProcessName  "cmd.exe")(eq EPOEvents.TargetProcessName  "cmd.exe"))']
        self._test_query_assertions(query, queries)



    def test_comp_exp_using_OR_with_qualifier(self):
        """
        Test with OR operator with qualifer
        """
        stix_pattern = "[process:name = 'cmd.exe'] OR [ipv4-addr:value = '00.00.00.00'] START t'2020-05-06T00:04:52.937Z' STOP t'2019-05-11T00:04:52.937Z'"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (or (or(eq EPOEvents.SourceProcessName  "cmd.exe")(eq EPOEvents.TargetProcessName  "cmd.exe")) (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))) (ge EPOEvents.DetectedUTC "2020-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2019-05-11 00:04:52.937")) ']
        self._test_query_assertions(query, queries)


    def test_comp_exp_using_OR_without_qualifier(self):
        """
        Test with OR operator
        """
        stix_pattern = "[process:name = 'cmd.exe'] OR [ipv4-addr:value = '00.00.00.00']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(or (or(eq EPOEvents.SourceProcessName  "cmd.exe")(eq EPOEvents.TargetProcessName  "cmd.exe")) (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))))']
        self._test_query_assertions(query, queries)


    def test_comp_exp_using_AND_without_qualifier(self):
        """
        Test with AND operator
        """
        stix_pattern = "[process:name = 'ftp.exe' AND process:name = 'ftp1.exe']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (or(eq EPOEvents.SourceProcessName  "ftp1.exe")(eq EPOEvents.TargetProcessName  "ftp1.exe")) (or(eq EPOEvents.SourceProcessName  "ftp.exe")(eq EPOEvents.TargetProcessName  "ftp.exe")))']
        self._test_query_assertions(query, queries)

    def test_comp_exp_using_AND_with_qualifier(self):
        """
        Test with AND operator
        """
        stix_pattern = "[file:name ='sathya' AND url:value = 'www.sathya1.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-06-28T12:54:01.009Z'"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (and (eq EPOEvents.SourceURL  "www.sathya1.com") (eq EPOEvents.TargetFileName  "sathya")) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-06-28 12:54:01.009")) ']
        self._test_query_assertions(query, queries)


    def test_comp_exp_using_AND(self):
        """
        Test with AND operator
        """
        stix_pattern = "[file:name ='sample']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(eq EPOEvents.TargetFileName  "sample")']
        self._test_query_assertions(query, queries)


    def test_network_comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[process:name = 'ftp.exe'] OR [file:name ='sample' AND file:name ='sample1'] START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-11T00:04:52.937Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (or(eq EPOEvents.SourceProcessName  "ftp.exe")(eq EPOEvents.TargetProcessName  "ftp.exe")) (and (eq EPOEvents.TargetFileName  "sample1") (eq EPOEvents.TargetFileName  "sample"))) (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-11 00:04:52.937")) ']

            self._test_query_assertions(query, queries)


    def test_network_1comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port = 37020 AND network-traffic:dst_port = 635] OR [ipv4-addr:value = '00.00.00.00'] AND [url:value = 'www.example.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-06-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (eq EPOEvents.SourceURL  "www.example.com")) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-06-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)



    def test_network_2comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern ="[process:name = 'ftp1.exe'] OR [file:name ='sample1' OR file:name ='sample2']"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(or (or(eq EPOEvents.SourceProcessName  "ftp1.exe")(eq EPOEvents.TargetProcessName  "ftp1.exe")) (or (eq EPOEvents.TargetFileName  "sample2") (eq EPOEvents.TargetFileName  "sample1")))']

            self._test_query_assertions(query, queries)



    def test_network_3comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern ="[network-traffic:src_port = 37020 OR network-traffic:dst_port = 21] OR [ipv4-addr:value = '00.00.00.00'] AND [url:value = 'www.sathya.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-06-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (eq EPOEvents.TargetPort  "21") (or (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (eq EPOEvents.SourceURL  "www.sathya.com"))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-06-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)


    def test_network_4comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port = 37020 AND network-traffic:dst_port = 21] OR [ipv4-addr:value = '00.00.00.00'] AND [url:value LIKE '%.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (endsWith EPOEvents.SourceURL  ".com")) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)



    def test_network_5comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[process:name LIKE 'explorer' OR file:name LIKE 'sathya']START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-28T00:04:52.937Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (contains EPOEvents.TargetFileName  "sathya") (or(contains EPOEvents.SourceProcessName  "explorer")(contains EPOEvents.TargetProcessName  "explorer"))) (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-28 00:04:52.937")) ']

            self._test_query_assertions(query, queries)


    def test_network_6comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port < 37020 OR network-traffic:dst_port >= '21'] OR [ipv4-addr:value = '00.00.00.00' AND url:value LIKE 'www'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (ge EPOEvents.TargetPort  "21") (and (contains EPOEvents.SourceURL  "www") (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)


    def test_network_7comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port = 37020 AND network-traffic:dst_port = 21] OR [ipv4-addr:value = '00.00.00.00' AND url:value LIKE 'www%'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (and (startsWith EPOEvents.SourceURL  "www") (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)



    def test_network_8comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port  < 37020 OR network-traffic:dst_port >= 21] OR [ipv4-addr:value = '00.00.00.00' AND url:value LIKE '%www%'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (ge EPOEvents.TargetPort  "21") (and (contains EPOEvents.SourceURL  "www") (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)



    def test_network_9comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port = 37020 AND network-traffic:dst_port = 21] OR [ipv4-addr:value = '00.00.00.00' AND url:value LIKE 'www'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (and (contains EPOEvents.SourceURL  "www") (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)



    def test_network_10comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:dst_port NOT = 21] OR [ipv4-addr:value = '00.00.00.00'] OR [url:value = 'www.sathya.com']"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(or (or NOT ((eq EPOEvents.TargetPort  "21")) (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))) (eq EPOEvents.SourceURL  "www.sathya.com"))']

            self._test_query_assertions(query, queries)



    def test_network_11comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port NOT = 37020 AND network-traffic:dst_port != 635] OR [ipv4-addr:value = '00.00.00.00'] OR [url:value = 'www.example.com']"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(or (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (eq EPOEvents.SourceURL  "www.example.com"))']

            self._test_query_assertions(query, queries)


    def test_network_12comb_obs_exp(self):
            """
            Test with two observation expression
            """
            stix_pattern = "[network-traffic:src_port = 37020 OR network-traffic:dst_port = 21] AND [ipv4-addr:value = '00.00.00.00'] AND [url:value = 'www.sathya.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2019-01-28T12:54:01.009Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (or (eq EPOEvents.TargetPort  "21") (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00")))) (eq EPOEvents.SourceURL  "www.sathya.com")) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2019-01-28 12:54:01.009")) ']

            self._test_query_assertions(query, queries)

    def test_network_13comb_obs_exp(self):
        """
        Test with two observation expression
        """
        stix_pattern = "[network-traffic:dst_port = 21] OR [ipv4-addr:value = '00.00.00.00'] AND [url:value = 'www.example.com'] START t'2019-01-28T12:24:01.009Z' STOP t'2020-05-25T12:54:01.009Z'"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (or (eq EPOEvents.TargetPort  "21") (or (or(eq EPOEvents.SourceIPV4  (ipv4 "00.00.00.00"))(eq EPOEvents.TargetIPV4  (ipv4 "00.00.00.00"))) (eq EPOEvents.SourceURL  "www.example.com"))) (ge EPOEvents.DetectedUTC "2019-01-28 12:24:01.009" ) (le EPOEvents.DetectedUTC  "2020-05-25 12:54:01.009")) ']

        self._test_query_assertions(query, queries)


    def test_network_custom_comb_obs_exp(self):
        """
        Test with two observation expression
        """
        stix_pattern = "[x_com_mcafee_epo:threat_type ='IDS_FW_THREAT_TYPE_INTRUSION'] AND [x_com_mcafee_epo:threat_action_taken LIKE 'blo'] START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-28T00:04:52.937Z'"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(and (or (eq EPOEvents.ThreatType  "IDS_FW_THREAT_TYPE_INTRUSION") (contains EPOEvents.ThreatActionTaken  "blo")) (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-28 00:04:52.937")) ']

        self._test_query_assertions(query, queries)




    def test_comp_exp_using_LIKE(self):
            """
            Test with Like operator
            """
            stix_pattern = "[process:name LIKE 'explorer']"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(or(contains EPOEvents.SourceProcessName  "explorer")(contains EPOEvents.TargetProcessName  "explorer"))']

            self._test_query_assertions(query, queries)




    def test_comp_exp_usingLike_without_qualifier(self):
            """
            Test with Like operator
            """
            stix_pattern = "[process:name LIKE 'explorer' OR file:name LIKE 'sample']"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(or (contains EPOEvents.TargetFileName  "sample") (or(contains EPOEvents.SourceProcessName  "explorer")(contains EPOEvents.TargetProcessName  "explorer")))']

            self._test_query_assertions(query, queries)



    def test_comp_exp_usingLike_with_Qualifier(self):
            """
            Test with Like operator with qualifier
            """
            stix_pattern = "[process:name LIKE 'explorer']START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-28T00:04:52.937Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or(contains EPOEvents.SourceProcessName  "explorer")(contains EPOEvents.TargetProcessName  "explorer")) (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-28 00:04:52.937")) ']

            self._test_query_assertions(query, queries)


    def test_comp_exp_usingLike_withQualifer_sample2(self):
            """
            Test with Like operator with qualifier
            """
            stix_pattern = "[process:name LIKE 'explorer' OR file:name LIKE 'sample']START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-28T00:04:52.937Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (or (contains EPOEvents.TargetFileName  "sample") (or(contains EPOEvents.SourceProcessName  "explorer")(contains EPOEvents.TargetProcessName  "explorer"))) (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-28 00:04:52.937")) ']

            self._test_query_assertions(query, queries)


    def test_network_custom_obs_exp(self):
            """
            Test with Customised events using Like operator with qualifier
            """
            stix_pattern = "[x_com_mcafee_epo:threat_action_taken LIKE 'blo'] START t'2019-05-06T00:04:52.937Z' STOP t'2020-05-28T00:04:52.937Z'"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(and (contains EPOEvents.ThreatActionTaken  "blo") (ge EPOEvents.DetectedUTC "2019-05-06 00:04:52.937" ) (le EPOEvents.DetectedUTC  "2020-05-28 00:04:52.937")) ']

            self._test_query_assertions(query, queries)


    def test_ge_comp_exp(self):
            """
            Test with Customised events using Like operator with qualifier
            """
            stix_pattern = "[network-traffic:dst_port >= 25]"
            query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
            queries = ['target=EPOEvents&where=(ge EPOEvents.TargetPort  "25")']
            self._test_query_assertions(query, queries)

    def test_le_comp_exp(self):
        """
        Test with Customised events using Like operator with qualifier
        """
        stix_pattern = "[network-traffic:dst_port <= 25]"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        queries = ['target=EPOEvents&where=(le EPOEvents.TargetPort  "25")']
        self._test_query_assertions(query, queries)



    def test_oper_issuperset(self):
        """
        Test Unsupportted operator
        """
        stix_pattern = "[ipv4-addr:value ISSUPERSET '54.239.30.177']"
        query = translation.translate('mcafee_epo_events', 'query', '{}', stix_pattern)
        assert query['success'] is False
        assert query['code'] == 'not_implemented'
        assert query['error'] == 'wrong parameter : Comparison operator IsSuperSet unsupported for McAfee ePO connector'