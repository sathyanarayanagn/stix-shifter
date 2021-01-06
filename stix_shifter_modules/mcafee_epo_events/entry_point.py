#from stix_shifter_utils.utils.entry_point_base import EntryPointBase
from stix_shifter_utils.utils.base_entry_point import BaseEntryPoint
#from .stix_translation.data_mapper import DataMapper
#from .stix_transmission.mcafee_epo_events_connector import Connector

from stix_shifter_utils.stix_translation.src.json_to_stix.json_to_stix import JSONToStix


# class EntryPoint(BaseEntryPoint):
#
#     def __init__(self, connection={}, configuration={}, options={}):
#         super().__init__(options)
#         if connection:
#             connector = Connector(connection, configuration)
#             self.setup_transmission_basic(connector)
#         else:
#             self.add_dialect('default', data_mapper=DataMapper(options), default=True)


class EntryPoint(BaseEntryPoint):

    def __init__(self, connection={}, configuration={}, options={}):
        super().__init__(connection, configuration, options)
        self.set_async(False)

        if connection:
            self.setup_transmission_basic(connection, configuration)
        else:
            self.add_dialect('default', default=True)