from typing import Optional

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
    FieldMappingTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
)

from ..kusto_common.errors import InvalidFieldTransformation
from ..kusto_common.postprocessing import create_prepend_query_table_item
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
    MICROSOFT_XDR_FIELD_MAPPINGS,
)
from .schema import MicrosoftXDRSchema
from .tables import MICROSOFT_XDR_TABLES
from .transformations import (
    LogonIdValueTransformation,
    ParentImageValueTransformation,
    SplitDomainUserTransformation,
    XDRHashesValuesTransformation,
)

MICROSOFT_XDR_SCHEMA = create_schema(MicrosoftXDRSchema, MICROSOFT_XDR_TABLES)

# Mapping from ParentImage to InitiatingProcessParentFileName. Must be used alongside of ParentImageValueTransformation
parent_image_field_mapping = {"ParentImage": "InitiatingProcessParentFileName"}


## Factory functions to create fresh ProcessingItems for each pipeline instance
def _create_drop_eventid_item():
    """Drop EventID field"""
    return ProcessingItem(
        identifier="microsoft_xdr_drop_eventid",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(["EventID", "EventCode", "ObjectType"])],
    )


def _create_fieldmappings_item():
    """Field mappings"""
    return ProcessingItem(
        identifier="microsoft_xdr_table_fieldmappings",
        transformation=DynamicFieldMappingTransformation(MICROSOFT_XDR_FIELD_MAPPINGS),
    )


def _create_generic_field_mappings_item():
    """Generic Field Mappings, keep this last.
    Exclude any fields already mapped, e.g. if a table mapping has been applied.
    This will fix the case where ProcessId is usually mapped to InitiatingProcessId,
    EXCEPT for the DeviceProcessEvent table where it stays as ProcessId.
    """
    return ProcessingItem(
        identifier="microsoft_xdr_generic_fieldmappings",
        transformation=GenericFieldMappingTransformation(MICROSOFT_XDR_FIELD_MAPPINGS),
        detection_item_conditions=[DetectionItemProcessingItemAppliedCondition("microsoft_xdr_table_fieldmappings")],
        detection_item_condition_linking=any,
        detection_item_condition_negation=True,
    )


def _create_replacement_items():
    """Field Value Replacements ProcessingItems.
    Sysmon uses abbreviations in RegistryKey values, replace with full key names
    as the DeviceRegistryEvents schema expects them to be.
    """
    return [
        # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
        ProcessingItem(
            identifier="microsoft_xdr_registry_key_replace_currentcontrolset",
            transformation=ReplaceStringTransformation(
                regex=r"(?i)(^HKLM\\SYSTEM\\CurrentControlSet)",
                replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001",
            ),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
        ),
        ProcessingItem(
            identifier="microsoft_xdr_registry_key_replace_hklm",
            transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM)", replacement=r"HKEY_LOCAL_MACHINE"),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
        ),
        ProcessingItem(
            identifier="microsoft_xdr_registry_key_replace_hku",
            transformation=ReplaceStringTransformation(regex=r"(?i)(^HKU)", replacement=r"HKEY_USERS"),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
        ),
        ProcessingItem(
            identifier="microsoft_xdr_registry_key_replace_hkcr",
            transformation=ReplaceStringTransformation(
                regex=r"(?i)(^HKCR)", replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"
            ),
            field_name_conditions=[IncludeFieldCondition(["RegistryKey", "PreviousRegistryKey"])],
        ),
        ProcessingItem(
            identifier="microsoft_xdr_registry_actiontype_value",
            transformation=RegistryActionTypeValueTransformation(),
            field_name_conditions=[IncludeFieldCondition(["ActionType"])],
        ),
        # Extract Domain from Username fields
        ProcessingItem(
            identifier="microsoft_xdr_domain_username_extract",
            transformation=SplitDomainUserTransformation(),
            field_name_conditions=[IncludeFieldCondition(["AccountName", "InitiatingProcessAccountName"])],
        ),
        ProcessingItem(
            identifier="microsoft_xdr_hashes_field_values",
            transformation=XDRHashesValuesTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Hashes"])],
        ),
        # Transform LogonId values to ensure exact matching (== instead of =~)
        ProcessingItem(
            identifier="microsoft_xdr_logonid_value_transform",
            transformation=LogonIdValueTransformation(),
            field_name_conditions=[IncludeFieldCondition(["LogonId", "InitiatingProcessLogonId"])],
        ),
        # Processing item to essentially ignore initiated field
        ProcessingItem(
            identifier="microsoft_xdr_network_initiated_field",
            transformation=DropDetectionItemTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Initiated"])],
            rule_conditions=[LogsourceCondition(category="network_connection")],
        ),
    ]


def _create_parent_image_items():
    """ParentImage -> InitiatingProcessParentFileName transformation items"""
    return [
        # First apply fieldmapping from ParentImage to InitiatingProcessParentFileName for non process-creation rules
        ProcessingItem(
            identifier="microsoft_xdr_parent_image_fieldmapping",
            transformation=FieldMappingTransformation(parent_image_field_mapping),  # type: ignore
            rule_conditions=[
                # Exclude process_creation events, there's direct field mapping in this schema table
                LogsourceCondition(category="process_creation")
            ],
            rule_condition_negation=True,
        ),
        # Second, extract the parent process name from the full path
        ProcessingItem(
            identifier="microsoft_xdr_parent_image_name_value",
            transformation=ParentImageValueTransformation(),
            field_name_conditions=[
                IncludeFieldCondition(["InitiatingProcessParentFileName"]),
            ],
            rule_conditions=[
                # Exclude process_creation events, there's direct field mapping in this schema table
                LogsourceCondition(category="process_creation")
            ],
            rule_condition_negation=True,
        ),
    ]


def _get_valid_fields(table_name):
    """Get valid fields for a given table name"""
    return (
        list(MICROSOFT_XDR_SCHEMA.tables[table_name].fields.keys())
        + list(MICROSOFT_XDR_FIELD_MAPPINGS.table_mappings.get(table_name, {}).keys())
        + list(MICROSOFT_XDR_FIELD_MAPPINGS.generic_mappings.keys())
        + ["Hashes"]
    )


def _create_rule_error_items():
    """Exceptions/Errors ProcessingItems.
    Catch-all for when the query table is not set, meaning the rule could
    not be mapped to a table or the table name was not set.
    """
    return [
        # Category Not Supported or Query Table Not Set
        ProcessingItem(
            identifier="microsoft_xdr_unsupported_rule_category_or_missing_query_table",
            transformation=RuleFailureTransformation(
                "Rule category not yet supported by the Microsoft XDR pipeline or query_table is not set."
            ),
            rule_conditions=[
                RuleProcessingItemAppliedCondition("microsoft_xdr_set_query_table"),  # type: ignore
                RuleProcessingStateCondition("query_table", None),  # type: ignore
            ],
            rule_condition_linking=all,
        )
    ]


def _create_field_error_items():
    """Create field validation error items for each table"""
    items = []

    for table_name in MICROSOFT_XDR_SCHEMA.tables.keys():
        valid_fields = _get_valid_fields(table_name)

        items.append(
            ProcessingItem(
                identifier=f"microsoft_xdr_unsupported_fields_{table_name}",
                transformation=InvalidFieldTransformation(
                    f"Please use valid fields for the {table_name} table, or the following fields that have keymappings in this "
                    f"pipeline:\n{', '.join(sorted(set(valid_fields)))}"
                ),
                field_name_conditions=[ExcludeFieldCondition(fields=valid_fields)],
                rule_conditions=[
                    RuleProcessingItemAppliedCondition("microsoft_xdr_set_query_table"),
                    RuleProcessingStateCondition("query_table", table_name),
                ],
                rule_condition_linking=all,
            )
        )

    # Add a catch-all error for custom table names
    items.append(
        ProcessingItem(
            identifier="microsoft_xdr_unsupported_fields_custom",
            transformation=InvalidFieldTransformation(
                "Invalid field name for the custom table. Please ensure you're using valid fields for your custom table."
            ),
            field_name_conditions=[
                ExcludeFieldCondition(fields=list(MICROSOFT_XDR_FIELD_MAPPINGS.generic_mappings.keys()) + ["Hashes"])
            ],
            rule_conditions=[
                RuleProcessingItemAppliedCondition("microsoft_xdr_set_query_table"),  # type: ignore
                RuleProcessingStateCondition("query_table", None),  # type: ignore
            ],
            rule_condition_linking=all,
        )
    )

    return items


def microsoft_xdr_pipeline(
    transform_parent_image: Optional[bool] = True, query_table: Optional[str] = None
) -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use in the Kusto Query Language backend.
    Field mappings based on documentation found here:
    https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-language?view=o365-worldwide

    :param query_table: If specified, the table name will be used in the finalizer, otherwise the table name will be selected based on the category of the rule.
    :type query_table: Optional[str]
    :param transform_parent_image: If True, the ParentImage field will be mapped to InitiatingProcessParentFileName, and
    the parent process name in the ParentImage will be extracted and used. This is because the Microsoft 365 Defender
    table schema does not contain a InitiatingProcessParentFolderPath field like it does for InitiatingProcessFolderPath.
    i.e. ParentImage: C:\\Windows\\System32\\whoami.exe -> InitiatingProcessParentFileName: whoami.exe.
    Defaults to True
    :type transform_parent_image: Optional[bool]

    :return: ProcessingPipeline for Microsoft 365 Defender Backend
    :rtype: ProcessingPipeline
    """

    pipeline_items = [
        ProcessingItem(
            identifier="microsoft_xdr_set_query_table",
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

    if transform_parent_image:
        pipeline_items[4:4] = _create_parent_image_items()

    return ProcessingPipeline(
        name="Generic Log Sources to Windows XDR tables and fields",
        priority=10,
        items=pipeline_items,
        allowed_backends=frozenset(["kusto"]),
        postprocessing_items=[create_prepend_query_table_item()],
    )
