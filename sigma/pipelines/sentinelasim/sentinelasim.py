from typing import Optional

from sigma.pipelines.kusto_common.postprocessing import create_prepend_query_table_item
from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    ExcludeFieldCondition,
    IncludeFieldCondition,
    LogsourceCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    DropDetectionItemTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
    SetStateTransformation,
)

from ..kusto_common.errors import InvalidFieldTransformation
from ..kusto_common.schema import create_schema
from ..kusto_common.transformations import (
    DynamicFieldMappingTransformation,
    GenericFieldMappingTransformation,
    RegistryActionTypeValueTransformation,
    SetQueryTableStateTransformation,
)
from .mappings import (
    CATEGORY_TO_TABLE_MAPPINGS,
    EVENTID_CATEGORY_TO_TABLE_MAPPINGS,
    SENTINEL_ASIM_FIELD_MAPPINGS,
)
from .schema import SentinelASIMSchema
from .tables import SENTINEL_ASIM_TABLES
from .transformations import (
    FileEventHashesValuesTransformation,
    ProcessCreateHashesValuesTransformation,
    WebSessionHashesValuesTransformation,
)

SENTINEL_ASIM_SCHEMA = create_schema(SentinelASIMSchema, SENTINEL_ASIM_TABLES)


## Factory functions to create fresh ProcessingItems for each pipeline instance
def _create_drop_eventid_item():
    """Drop EventID field"""
    return ProcessingItem(
        identifier="sentinel_asim_drop_eventid",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(["EventID", "EventCode", "ObjectType"])],
    )


def _create_fieldmappings_item():
    """Field mappings"""
    return ProcessingItem(
        identifier="sentinel_asim_table_fieldmappings",
        transformation=DynamicFieldMappingTransformation(SENTINEL_ASIM_FIELD_MAPPINGS),
    )


def _create_generic_field_mappings_item():
    """Generic Field Mappings, keep this last.
    Exclude any fields already mapped, e.g. if a table mapping has been applied.
    """
    return ProcessingItem(
        identifier="sentinel_asim_generic_fieldmappings",
        transformation=GenericFieldMappingTransformation(SENTINEL_ASIM_FIELD_MAPPINGS),
        detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("sentinel_asim_table_fieldmappings")],
        detection_item_condition_linking=any,
        detection_item_condition_negation=True,
    )


def _create_replacement_items():
    """Field Value Replacements ProcessingItems"""
    return [
        # Sysmon uses abbreviations in RegistryKey values, replace with full key names as the DeviceRegistryEvents schema
        # expects them to be
        # Note: Ensure this comes AFTER field mapping renames, as we're specifying DeviceRegistryEvent fields
        #
        # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
        ProcessingItem(
            identifier="sentinel_asim_registry_key_replace_currentcontrolset",
            transformation=ReplaceStringTransformation(
                regex=r"(?i)(^HKLM\\SYSTEM\\CurrentControlSet)",
                replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001",
            ),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
        ),
        ProcessingItem(
            identifier="sentinel_asim_registry_key_replace_hklm",
            transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM)", replacement=r"HKEY_LOCAL_MACHINE"),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "RegistryPreviousKey"])],
        ),
        ProcessingItem(
            identifier="sentinel_asim_registry_key_replace_hku",
            transformation=ReplaceStringTransformation(regex=r"(?i)(^HKU)", replacement=r"HKEY_USERS"),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "RegistryPreviousKey"])],
        ),
        ProcessingItem(
            identifier="sentinel_asim_registry_key_replace_hkcr",
            transformation=ReplaceStringTransformation(
                regex=r"(?i)(^HKCR)", replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"
            ),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "RegistryPreviousKey"])],
        ),
        ProcessingItem(
            identifier="sentinel_asim_registry_actiontype_value",
            transformation=RegistryActionTypeValueTransformation(),
            field_name_conditions=[IncludeFieldCondition(["EventType"])],
        ),
        # Processing item to transform the Hashes field in the SecurityEvent table to get rid of the hash algorithm prefix in each value
        ProcessingItem(
            identifier="sentinel_asim_processcreate_hashes_field_values",
            transformation=ProcessCreateHashesValuesTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Hashes"])],
            rule_conditions=[RuleProcessingStateCondition("query_table", "imProcessCreate")],
        ),
        ProcessingItem(
            identifier="sentinel_asim_fileevent_hashes_field_values",
            transformation=FileEventHashesValuesTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Hashes"])],
            rule_conditions=[RuleProcessingStateCondition("query_table", "imFileEvent")],
        ),
        ProcessingItem(
            identifier="sentinel_asim_webrequest_hashes_field_values",
            transformation=WebSessionHashesValuesTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Hashes"])],
            rule_conditions=[RuleProcessingStateCondition("query_table", "imWebSession")],
        ),
        # Processing item to essentially ignore initiated field
        ProcessingItem(
            identifier="sentinel_asim_network_initiated_field",
            transformation=DropDetectionItemTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Initiated"])],
            rule_conditions=[LogsourceCondition(category="network_connection")],
        ),
    ]


def _create_rule_error_items():
    """Exceptions/Errors ProcessingItems.
    Catch-all for when the query table is not set.
    """
    return [
        # Category Not Supported or Query Table Not Set
        ProcessingItem(
            identifier="sentinel_asim_unsupported_rule_category_or_missing_query_table",
            transformation=RuleFailureTransformation(
                "Rule category not yet supported by the Sentinel ASIM pipeline or query_table is not set."
            ),
            rule_conditions=[
                RuleProcessingItemAppliedCondition("sentinel_asim_set_query_table"),  # type: ignore
                RuleProcessingStateCondition("query_table", None),  # type: ignore
            ],
            rule_condition_linking=all,
        )
    ]


def _get_valid_fields(table_name):
    return (
        list(SENTINEL_ASIM_SCHEMA.tables[table_name].fields.keys())
        + list(SENTINEL_ASIM_FIELD_MAPPINGS.table_mappings.get(table_name, {}).keys())
        + list(SENTINEL_ASIM_FIELD_MAPPINGS.generic_mappings.keys())
        + ["Hashes"]
    )


def _create_field_error_items():
    """Create field validation error items for each table"""
    items = []

    for table_name in SENTINEL_ASIM_SCHEMA.tables.keys():
        valid_fields = _get_valid_fields(table_name)

        items.append(
            ProcessingItem(
                identifier=f"sentinel_asim_unsupported_fields_{table_name}",
                transformation=InvalidFieldTransformation(
                    f"Please use valid fields for the {table_name} table, or the following fields that have fieldmappings in this "
                    f"pipeline:\n{', '.join(sorted(set(valid_fields)))}"
                ),
                field_name_conditions=[ExcludeFieldCondition(fields=valid_fields)],
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("sentinel_asim_set_query_table"),  # type: ignore
                    RuleProcessingStateCondition("query_table", table_name),  # type: ignore
                ],
                rule_condition_linking=all,
            )
        )

    # Add a catch-all error for custom table names
    items.append(
        ProcessingItem(
            identifier="sentinel_asim_unsupported_fields_custom",
            transformation=InvalidFieldTransformation(
                "Invalid field name for the custom table. Please ensure you're using valid fields for your custom table."
            ),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(SENTINEL_ASIM_FIELD_MAPPINGS.generic_mappings.keys()) + ["Hashes"])
            ],
            rule_conditions=[
                RuleProcessingItemAppliedCondition("sentinel_asim_set_query_table"),  # type: ignore
                RuleProcessingStateCondition("query_table", None),  # type: ignore
            ],
            rule_condition_linking=all,
        )
    )

    return items


def sentinel_asim_pipeline(
    transform_parent_image: Optional[bool] = True, query_table: Optional[str] = None
) -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use in the Kusto Query Language backend.

    :param query_table: If specified, the table name will be used in the finalizer, otherwise the table name will be selected based on the category of the rule.
    :type query_table: Optional[str]

    :return: ProcessingPipeline for Microsoft Sentinel ASIM
    :rtype: ProcessingPipeline
    """

    pipeline_items = [
        ProcessingItem(
            identifier="sentinel_asim_set_timestamp_field",
            transformation=SetStateTransformation(key="timestamp_field", val="TimeGenerated"),
        ),
        ProcessingItem(
            identifier="sentinel_asim_set_query_table",
            transformation=SetQueryTableStateTransformation(
                query_table, CATEGORY_TO_TABLE_MAPPINGS, EVENTID_CATEGORY_TO_TABLE_MAPPINGS
            ),
        ),
        _create_drop_eventid_item(),
        _create_fieldmappings_item(),
        _create_generic_field_mappings_item(),
        *_create_replacement_items(),
        *_create_rule_error_items(),
        *_create_field_error_items(),
    ]

    return ProcessingPipeline(
        name="Generic Log Sources to Sentinel ASIM tables and fields",
        priority=10,
        items=pipeline_items,
        allowed_backends=frozenset(["kusto"]),
        postprocessing_items=[create_prepend_query_table_item()],
    )
