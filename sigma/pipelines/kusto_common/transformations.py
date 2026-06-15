import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Union

from sigma.conditions import ConditionOR
from sigma.correlations import SigmaCorrelationRule
from sigma.processing.transformations import FieldMappingTransformation, Transformation
from sigma.processing.transformations.base import DetectionItemTransformation, ValueTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import SigmaString, SigmaType

from ..kusto_common.mappings import get_table_from_eventid
from ..kusto_common.schema import FieldMappings
from .errors import InvalidHashAlgorithmError, SigmaTransformationError


class DynamicFieldMappingTransformation(FieldMappingTransformation):
    """
    Dynamically sets the mapping dictionary based on the pipeline state or rule's category.

    :param field_mappings: A FieldMappings schema object that contains the table_mappings and generic_mappings.
    :type field_mappings: FieldMappings schema object
    """

    def __init__(self, field_mappings: FieldMappings):
        super().__init__(field_mappings.generic_mappings)  # type: ignore
        self.field_mappings = field_mappings

    def set_dynamic_mapping(self, pipeline):
        """
        Set the mapping dynamically based on the pipeline state 'query_table' or the rule's logsource category.
        """

        # We should always have a query_table in the pipeline state, will implement mapping based on rule category later if not
        if "query_table" in pipeline.state:
            query_table = pipeline.state["query_table"]
            self.mapping = self.field_mappings.table_mappings.get(query_table, {})
        else:
            # TODO: Implement mapping based on rule category
            pass

    def apply(
        self,
        rule: Union["SigmaRule", "SigmaCorrelationRule"],  # noqa: F821 # type: ignore
    ) -> None:
        """Apply dynamic mapping before the field name transformations."""
        self.set_dynamic_mapping(self._pipeline)  # Dynamically update the mapping
        super().apply(rule)  # Call parent method to continue the transformation process


class GenericFieldMappingTransformation(FieldMappingTransformation):
    """
    Transformation for applying generic field mappings after table-specific mappings.
    """

    def __init__(self, field_mappings: FieldMappings):
        super().__init__(field_mappings.generic_mappings)  # type: ignore

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetectionItem, SigmaString]]:
        if detection_item.field in self.mapping:
            detection_item.field = self.mapping[detection_item.field]  # type: ignore
        return detection_item


class BaseHashesValuesTransformation(DetectionItemTransformation):
    """
    Base class for transforming the Hashes field to get rid of the hash algorithm prefix in each value and create new detection items for each hash type.
    """

    def __init__(self, valid_hash_algos: List[str], field_prefix: Optional[str] = None, drop_algo_prefix: bool = False):
        """
        :param valid_hash_algos: A list of valid hash algorithms that are supported by the table.
        :param field_prefix: The prefix to use for the new detection items.
        :param drop_algo_prefix: Whether to drop the algorithm prefix in the new field name, e.g. "FileHashSHA256" -> "FileHash".
        """
        self.valid_hash_algos = valid_hash_algos
        self.field_prefix = field_prefix or ""
        self.drop_algo_prefix = drop_algo_prefix

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        no_valid_hash_algo = True
        algo_dict = defaultdict(list)  # map to keep track of algos and lists of values
        if not isinstance(detection_item.value, list):
            detection_item.value = [detection_item.value]
        for d in detection_item.value:
            hash_value = d.to_plain().split("|")  # sometimes if ALGO|VALUE
            if len(hash_value) == 1:  # and sometimes its ALGO=VALUE
                hash_value = hash_value[0].split("=")
            if len(hash_value) == 2:
                hash_algo = (
                    hash_value[0].lstrip("*").upper()
                    if hash_value[0].lstrip("*").upper() in self.valid_hash_algos
                    else ""
                )
                if hash_algo:
                    no_valid_hash_algo = False
                hash_value = hash_value[1]
            else:
                hash_value = hash_value[0]
                if len(hash_value) == 32:  # MD5
                    hash_algo = "MD5"
                    no_valid_hash_algo = False
                elif len(hash_value) == 40:  # SHA1
                    hash_algo = "SHA1"
                    no_valid_hash_algo = False
                elif len(hash_value) == 64:  # SHA256
                    hash_algo = "SHA256"
                    no_valid_hash_algo = False
                elif len(hash_value) == 128:  # SHA512
                    hash_algo = "SHA512"
                    no_valid_hash_algo = False
                else:  # Invalid algo, no fieldname for keyword search
                    hash_algo = ""

            field_name = self.field_prefix
            if not self.drop_algo_prefix:
                field_name += hash_algo
            algo_dict[field_name].append(hash_value)
        if no_valid_hash_algo:
            raise InvalidHashAlgorithmError(
                "No valid hash algo found in Hashes field. Please use one of the following: "
                + ", ".join(self.valid_hash_algos)
            )
        for k, v in algo_dict.items():
            if k:  # Filter out invalid hash algo types
                to_return.append(
                    SigmaDetectionItem(
                        field=k if k != "keyword" else None, modifiers=[], value=[SigmaString(x) for x in v]
                    )
                )
        return SigmaDetection(detection_items=to_return, item_linking=ConditionOR)


@dataclass
class SetQueryTableStateTransformation(Transformation):
    """Sets rule query table in pipeline state query_table key

    The following priority is used to determine the value to set:
    1) The value provided in the val argument
    2) If the query_table is already set in the pipeline state, use that value (e.g. set in a previous pipeline, like via YAML in sigma-cli for user-defined query tables)
    3) If the rule's logsource category is present in the category_to_table_mappings dictionary, use that value
    4) If the rule has an EventID, use the table name from the eventid_to_table_mappings dictionary
    5) If none of the above are present, raise an error

    :param val: The table name to set in the pipeline state. If not provided, the table name will be determined from the rule's logsource category.
    :param category_to_table_mappings: A dictionary mapping logsource categories to table names. If not provided, the default category_to_table_mappings will be used.

    """

    val: Any = None
    category_to_table_mappings: Dict[str, Any] = field(default_factory=dict)
    event_id_category_to_table_mappings: Dict[str, Any] = field(default_factory=dict)

    def apply_detection_item(self, detection_item: SigmaDetectionItem) -> Optional[str]:
        """
        Apply transformation on detection item. We need to set the query_table pipeline state key, so we return the table name string based on the EventID or EventCode.
        """
        if detection_item.field == "EventID" or detection_item.field == "EventCode":
            for value in detection_item.value:
                if table_name := get_table_from_eventid(
                    int(value.to_plain()), self.event_id_category_to_table_mappings
                ):
                    return table_name
        return None

    def apply_detection(self, detection: SigmaDetection) -> Optional[str]:
        """Apply transformation on detection. We need to set the event_type custom attribute on the rule, so we return the event_type string."""
        for i, detection_item in enumerate(detection.detection_items):
            if isinstance(detection_item, SigmaDetection):  # recurse into nested detection items
                self.apply_detection(detection_item)
            else:
                if (self.processing_item is None or self.processing_item.match_detection_item(detection_item)) and (
                    r := self.apply_detection_item(detection_item)
                ) is not None:
                    self.processing_item_applied(detection.detection_items[i])
                    return r

    def _get_table_name_from_sigma_rule(self, rule: SigmaRule) -> Optional[str]:
        if rule.logsource.category:
            return self.category_to_table_mappings.get(rule.logsource.category)

        for section_title, detection in rule.detection.detections.items():
            # We only want event types from selection sections, not filters
            if re.match(r"^sel.*", section_title.lower()):
                if (r := self.apply_detection(detection)) is not None:
                    return r

        return None

    def _get_table_name_from_correlation_rule(self, rule: SigmaCorrelationRule) -> Optional[str]:
        for rule_ref in rule.rules:
            ref_rule = getattr(rule_ref, "rule", None)
            if isinstance(ref_rule, SigmaRule):
                if (table_name := self._get_table_name_from_sigma_rule(ref_rule)) is not None:
                    return table_name

        return None

    def apply(self, rule: Union["SigmaRule", "SigmaCorrelationRule"]) -> None:  # type: ignore  # noqa: F821
        # Init table_name to None, will be set in the following if statements
        table_name = None
        # Set table_name based on the following priority:
        # 1) The value provided in the val argument
        if self.val:
            table_name = self.val
        # 2) If the query_table is already set in the pipeline state, use that value (e.g. set in a previous pipeline, like via YAML in sigma-cli for user-defined query tables)
        elif self._pipeline.state.get("query_table"):
            table_name = self._pipeline.state.get("query_table")
        # 3) If this is a correlation rule, derive table from referenced base rules.
        elif isinstance(rule, SigmaCorrelationRule):
            table_name = self._get_table_name_from_correlation_rule(rule)
        # 4) For standard rules, map from category/EventID.
        else:
            table_name = self._get_table_name_from_sigma_rule(rule)

        if table_name:
            if isinstance(table_name, list):
                table_name = table_name[0]  # Use the first table if it's a list
            self._pipeline.state["query_table"] = table_name
            # Store table on SigmaRule so multi-rule correlation can look up per-rule table names
            if isinstance(rule, SigmaRule):
                rule._kusto_query_table = table_name
            # Mark this processing item as applied so that RuleProcessingItemAppliedCondition works
            self.processing_item_applied(rule)
        else:
            raise SigmaTransformationError(
                f"Unable to determine table name from rule.  The query table is determined in the following order of priority:\n"
                f"  1) The value provided to processing pipeline's query_table parameter, if using a Python script.\n"
                f"  2) If the query_table is already set in the pipeline state, such as from a custom user-defined pipeline if using sigma-cli.\n"
                f"  3) If the rule's logsource category is present in the pipeline's category_to_table_mappings dictionary in mappings.py, use that value.\n"
                f"  4) If the rule has an EventID, use the table name from the pipeline's eventid_to_table_mappings dictionary in mappings.py.\n"
                f"For more details, see https://github.com/AttackIQ/pySigma-backend-kusto/blob/main/README.md#%EF%B8%8F-custom-table-names-new-in-030-beta."
            )


## Change field value AFTER field transformations from Sysmon values to values expected in the pipelines registry table action field
class RegistryActionTypeValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation. The Microsoft DeviceRegistryEvents table expect the ActionType to
    be a slightly different set of values than what Sysmon specified, so this will change them to the correct value."""

    value_mappings = {  # Sysmon EventType -> DeviceRegistryEvents ActionType
        "CreateKey": "RegistryKeyCreated",
        "DeleteKey": ["RegistryKeyDeleted", "RegistryValueDeleted"],
        "SetValue": "RegistryValueSet",
        "RenameKey": ["RegistryValueSet", "RegistryKeyCreated"],
    }

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        mapped_vals = self.value_mappings.get(val.to_plain(), val.to_plain())
        if isinstance(mapped_vals, list):
            return [SigmaString(v) for v in mapped_vals]
        return SigmaString(mapped_vals)
