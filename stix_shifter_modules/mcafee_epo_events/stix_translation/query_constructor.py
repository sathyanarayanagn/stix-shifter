from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import ObservationExpression, \
    ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators, StartStopQualifier
from stix_shifter_utils.stix_translation.src.utils.transformers import TimestampToMilliseconds
from stix_shifter_utils.stix_translation.src.json_to_stix import observable
import logging
import re
from datetime import datetime, timedelta

START_STOP_PATTERN_EPO = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.[0-9]{0,3}))"

START_STOP_PATTERN = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z)"
# Source and destination reference mapping for ip and mac addresses.
# Change the keys to match the data source fields. The value array indicates the possible data type that can come into from field.
REFERENCE_DATA_TYPES = {"SourceIpV4": ["ipv4", "ipv4_cidr"],
                        "SourceIpV6": ["ipv6"],
                        "DestinationIpV4": ["ipv4", "ipv4_cidr"],
                        "DestinationIpV6": ["ipv6"]}

logger = logging.getLogger(__name__)


class QueryStringPatternTranslator:
    # Change comparator values to match with supported data source operators
    comparator_lookup = {
        ComparisonExpressionOperators.And: "and",
        ComparisonExpressionOperators.Or: "or",
        ComparisonComparators.GreaterThan: "gt",
        ComparisonComparators.GreaterThanOrEqual: "ge",
        ComparisonComparators.LessThan: "lt",
        ComparisonComparators.LessThanOrEqual: "le",
        ComparisonComparators.Equal: "eq",
        ComparisonComparators.Like: "Contains",
        ObservationOperators.Or: 'or',
        ObservationOperators.And: 'or'
    }

    def __init__(self, pattern: Pattern, data_model_mapper, time_range):
        self.dmm = data_model_mapper
        self._time_range = time_range
        self.pattern = pattern
        self.time_range_str = ''
        self.translated = self.parse_expression(pattern)

    @staticmethod
    def _format_set(values) -> str:
        gen = values.element_iterator()
        return "({})".format(' OR '.join([QueryStringPatternTranslator._escape_value(value) for value in gen]))

    @staticmethod
    def _format_match(value) -> str:
        raw = QueryStringPatternTranslator._escape_value(value)
        if raw[0] == "^":
            raw = raw[1:]
        else:
            raw = ".*" + raw
        if raw[-1] == "$":
            raw = raw[0:-1]
        else:
            raw = raw + ".*"
        return "\"{}\"".format(raw)

    @staticmethod
    def _format_equality(value) -> str:
        return '\"{}\"'.format(value)

    def _format_equality_ip(self, value, field_type) -> str:
        return '(' + field_type + ' \"{}\"'.format(value) + ')'

    def _format_like(self,value) -> str:
        print("in format like")
        """
        Formatting value in the event of LIKE operation
        :param value: str
        :return: str
        """

        # Replacing value with % to .* and _ to . for supporting Like comparator
        if not isinstance(value, list):
            if value.startswith("%") and value.endswith("%"):
                return "contains"
            elif value.startswith("%"):
                return "endsWith"
            elif value.endswith("%"):
                return "startsWith"
            else:
                return "contains"


    @staticmethod
    def _escape_value(value, comparator=None) -> str:
        if isinstance(value, str):
            return '{}'.format(value.replace('\\', '\\\\').replace('\"', '\\"').replace('(', '\\(').replace(')', '\\)'))
        else:
            return value

    @staticmethod
    def _negate_comparison(comparison_string):
        return "NOT ({})".format(comparison_string)

    @staticmethod
    def _check_value_type(value):
        value = str(value)
        for key, pattern in observable.REGEX.items():
            if key != 'date' and bool(re.search(pattern, value)):
                return key
        return None

    @staticmethod
    def _parse_reference(self, stix_field, value_type, mapped_field, value, comparator):
        if value_type not in REFERENCE_DATA_TYPES["{}".format(mapped_field)]:
            return None
        else:
            return "{mapped_field} {comparator} {value}".format(
                mapped_field=mapped_field, comparator=comparator, value=value)

    @staticmethod
    def _parse_mapped_fields(self, expression, value, comparator, stix_field, mapped_fields_array):
        comparison_string = ""
        is_reference_value = self._is_reference_value(stix_field)
        # Need to use expression.value to match against regex since the passed-in value has already been formated.
        value_type = self._check_value_type(expression.value) if is_reference_value else None
        mapped_fields_count = 1 if is_reference_value else len(mapped_fields_array)

        for mapped_field in mapped_fields_array:
            if (mapped_fields_count > 1):
                comparison_string += "or"
                mapped_fields_count -= 1
            if is_reference_value:
                parsed_reference = self._parse_reference(self, stix_field, value_type, mapped_field, value, comparator)
                if not parsed_reference:
                    continue
                comparison_string += parsed_reference
            else:
                comparison_string += "({comparator} {mapped_field}  {value})".format(mapped_field=mapped_field,
                                                                                     comparator=comparator, value=value)
            if (mapped_fields_count > 1):
                comparison_string += " OR "
                mapped_fields_count -= 1
        return comparison_string

    @staticmethod
    def _is_reference_value(stix_field):
        return stix_field == 'src_ref.value' or stix_field == 'dst_ref.value'

    @staticmethod
    def _lookup_comparison_operator(self, expression_operator):
        if expression_operator not in self.comparator_lookup:
            raise NotImplementedError(
                "Comparison operator {} unsupported for McAfee ePO connector".format(expression_operator.name))
        return self.comparator_lookup[expression_operator]

    @staticmethod
    def _parse_time_range(self, qualifier, time_range):
        """
        :param qualifier: str, input time range i.e START t'2019-04-10T08:43:10.003Z' STOP t'2019-04-20T10:43:10.003Z'
        :param time_range: int, value available from main.py in options variable
        :return: str, format_string bound with time range provided
        """
        try:
            compile_timestamp_regex = re.compile(START_STOP_PATTERN)
            compile_timestamp_regex_epo = re.compile(START_STOP_PATTERN_EPO)
            mapped_field = "EPOEvents.DetectedUTC"
            if qualifier and compile_timestamp_regex.search(qualifier):
                time_range_iterator = compile_timestamp_regex.finditer(qualifier)
                time_range_list = [each.group().replace('T', ' ').replace('Z', '') for each in time_range_iterator]
            # Default time range Start time = Now - 5 minutes and Stop time = Now
            else:
                stop_time = datetime.utcnow()
                start_time = stop_time - timedelta(minutes=time_range)
                converted_starttime = start_time.strftime('%Y-%m-%d %H:%M:%S.000')
                converted_stoptime = stop_time.strftime('%Y-%m-%d %H:%M:%S.000')
                time_range_list = [converted_starttime, converted_stoptime]

            value = ('(ge {mapped_field} "{start_time}" ) (le {mapped_field}  "{stop_time}")'
                     ).format(mapped_field=mapped_field, start_time=time_range_list[0], stop_time=time_range_list[1])
            format_string = '{value}'.format(value=value)
            self.time_range_str = format_string

        except (KeyError, IndexError, TypeError) as e:
            raise e
        return ''

    def _parse_expression(self, expression, qualifier=None) -> str:
        if isinstance(expression, ComparisonExpression):  # Base Case
            # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            # Multiple data source fields may map to the same STIX Object
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            # Resolve the comparison symbol to use in the query string (usually just ':')
            comparator = self._lookup_comparison_operator(self, expression.comparator)

            if stix_field == 'start' or stix_field == 'end':
                transformer = TimestampToMilliseconds()
                expression.value = transformer.transform(expression.value)
            elif expression.comparator == ComparisonComparators.Equal or expression.comparator == ComparisonComparators.NotEqual:
                if stix_object == 'ipv4-addr' or stix_object == 'ipv6-addr':
                    field_type = "ipv4" if stix_object == 'ipv4-addr' else "ipv6"
                    value = self._format_equality_ip(expression.value, field_type)
                else:
                    value = self._format_equality(expression.value)
            elif expression.comparator == ComparisonComparators.Like:
                formatted_exp = self._format_like(expression.value)
                value = self._format_equality(format(expression.value.replace('%','')))
                comparator = formatted_exp

            elif expression.comparator == ComparisonComparators.GreaterThan or ComparisonComparators.GreaterThanOrEqual or ComparisonComparators.LessThan or ComparisonComparators.LessThanOrEqual:  # needs forward slashes
                value = self._format_equality(expression.value)
            else:
                value = self._escape_value(expression.value)

            comparison_string = self._parse_mapped_fields(self, expression, value, comparator, stix_field,
                                                          mapped_fields_array)
            if (len(mapped_fields_array) > 1 and not self._is_reference_value(stix_field)):
                grouped_comparison_string = "(" + comparison_string + ")"
                comparison_string = grouped_comparison_string
            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            if qualifier is not None:
                # time string to be attached after final string is formed
                self._parse_time_range(self, qualifier, self._time_range)
                return "{}".format(comparison_string)
            else:
                return "{}".format(comparison_string)
        elif isinstance(expression, CombinedComparisonExpression):
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if not expression_01 or not expression_02:
                return ''
            if isinstance(expression.expr1, CombinedComparisonExpression):
                expression_01 = "({})".format(expression_01)
            if isinstance(expression.expr2, CombinedComparisonExpression):
                expression_02 = "({})".format(expression_02)
            query_string = "({} {} {})".format(operator, expression_01, expression_02)
            if qualifier is not None:
                self._parse_time_range(self, qualifier, self._time_range)
                return "{}".format(query_string)
            else:
                return "{}".format(query_string)
        elif isinstance(expression, ObservationExpression):
            # return self._parse_expression(expression.comparison_expression, qualifier)
            return "{}".format(self._parse_expression(expression.comparison_expression, qualifier))
            # return "{}".format(self._parse_expression(expression.comparison_expression))

        elif hasattr(expression, 'qualifier') and hasattr(expression, 'observation_expression'):
            if isinstance(expression.observation_expression, CombinedObservationExpression):
                operator = self._lookup_comparison_operator(self, expression.observation_expression.operator)
                expression_01 = self._parse_expression(expression.observation_expression.expr1)
                expression_02 = self._parse_expression(expression.observation_expression.expr2, expression.qualifier)
                return "({} {} {})".format(operator, expression_01, expression_02)
            else:
                return self._parse_expression(expression.observation_expression.comparison_expression,
                                              expression.qualifier)
                # return self._parse_expression(expression.observation_expression.comparison_expression)
        elif isinstance(expression, CombinedObservationExpression):
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if expression_01 and expression_02:
                return "({} {} {})".format(operator, expression_01, expression_02)
            elif expression_01:
                return "({})".format(expression_01)
            elif expression_02:
                return "({})".format(expression_02)
            else:
                return ''
        elif isinstance(expression, StartStopQualifier):
            if hasattr(expression, 'observation_expression'):
                return self._parse_expression(getattr(expression, 'observation_expression'), expression.qualifier)
        elif isinstance(expression, Pattern):
            return "{expr}".format(expr=self._parse_expression(expression.expression))
        else:
            raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
                expression, type(expression)))

    def parse_expression(self, pattern: Pattern):
        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    timerange = options['time_range']
    query = QueryStringPatternTranslator(pattern, data_model_mapping, timerange)
    if query.time_range_str == "":
        return "target=EPOEvents&where={}".format(query.translated)
    else:
        return "target=EPOEvents&where=(and {} {}) ".format(query.translated, query.time_range_str)
