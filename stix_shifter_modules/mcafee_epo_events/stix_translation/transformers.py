from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer
import re
import socket


class FormatMcafeeProtocol(ValueTransformer):
    """A value transformer to convert TCP protocol to IANA format"""

    @staticmethod
    def transform(protocolname):
        # converted_name = re.search(r'^tcp', protocolName, re.I).group(0)
        try:
            obj_array = protocolname if isinstance(protocolname, list) else protocolname.split(', ')
            # Loop through entries inside obj_array and make all strings lowercase to meet STIX format
            obj_array = [entry.lower() for entry in obj_array]
            return obj_array
        except ValueError:
            print("Cannot convert input to array")


class McAfeeToTimestamp(ValueTransformer):
    """A value transformer for converting McAfee timestamp to regular timestamp"""

    @staticmethod
    def transform(ePOTime):
        rgx = r"(\d\d\d\d-\d\d-\d\d)\s(\d\d:\d\d:\d\d)"
        START_STOP_PATTERN_EPO = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
        mtch = (re.findall(START_STOP_PATTERN_EPO, ePOTime))[0]
        return (mtch) + '.000Z'


class McAfeeToIPv4(ValueTransformer):
    """A value transformer for converting McAfee IPv4 to regular IPv4"""

    @staticmethod
    def transform(ipv4int):
        try:
            ip = ((ipv4int - 2147483647) - 1)
            return socket.inet_ntoa((ip & 0xffffffff).to_bytes(4, "big"))
        except ValueError:
            print("Cannot convert input to IPv4 string")