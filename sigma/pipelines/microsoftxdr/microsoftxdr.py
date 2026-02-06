from typing import Optional

from sigma.processing.conditions import (
    DetectionItemProcessingItemAppliedCondition,
    ExcludeFieldCondition,
    IncludeFieldCondition,
    LogsourceCondition,
    RuleProcessingItemAppliedCondition,
    RuleProcessingStateCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline, QueryPostprocessingItem
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.processing.transformations import (
    AddConditionTransformation,
    DropDetectionItemTransformation,
    FieldMappingTransformation,
    ReplaceStringTransformation,
    RuleFailureTransformation,
)
from sigma.rule import SigmaRule

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
from .postprocessing import create_add_pipe_name_extend_item
from .schema import MicrosoftXDRSchema
from .tables import MICROSOFT_XDR_TABLES
from .transformations import (
    ImageToOriginalFileNameTransformation,
    ParentImageValueTransformation,
    PipeNameTransformation,
    SplitDomainUserTransformation,
    SplitFilePathTransformation,
    XDRHashesValuesTransformation,
)

MICROSOFT_XDR_SCHEMA = create_schema(MicrosoftXDRSchema, MICROSOFT_XDR_TABLES)

# Mapping from ParentImage to InitiatingProcessParentFileName. Must be used alongside of ParentImageValueTransformation
parent_image_field_mapping = {"ParentImage": "InitiatingProcessParentFileName"}


## Factory functions to create fresh ProcessingItems for each pipeline instance
def _create_set_query_table_item(query_table: Optional[str] = None):
    """Set query table state"""
    return ProcessingItem(
        identifier="microsoft_xdr_set_query_table",
        transformation=SetQueryTableStateTransformation(
            query_table, CATEGORY_TO_TABLE_MAPPINGS, EVENTID_CATEGORY_TO_TABLE_MAPPINGS
        ),
    )


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
        # Processing item to essentially ignore initiated field
        ProcessingItem(
            identifier="microsoft_xdr_network_initiated_field",
            transformation=DropDetectionItemTransformation(),
            field_name_conditions=[IncludeFieldCondition(["Initiated"])],
            rule_conditions=[LogsourceCondition(category="network_connection")],
        ),
    ]


def _create_remote_thread_items():
    """Processing items for create_remote_thread category"""
    return [
        # Add ActionType condition for create_remote_thread events
        # This is needed because DeviceEvents table contains many ActionTypes
        ProcessingItem(
            identifier="microsoft_xdr_create_remote_thread_actiontype",
            transformation=AddConditionTransformation({"ActionType": "CreateRemoteThreadApiCall"}),
            rule_conditions=[LogsourceCondition(category="create_remote_thread")],
        ),
        # Split TargetImage into FolderPath and FileName for create_remote_thread
        # In DeviceEvents, FileName is just the executable name, FolderPath is the directory
        ProcessingItem(
            identifier="microsoft_xdr_create_remote_thread_target_image_split",
            transformation=SplitFilePathTransformation(),
            field_name_conditions=[IncludeFieldCondition(["TargetImage"])],
            rule_conditions=[LogsourceCondition(category="create_remote_thread")],
        ),
    ]


def _create_pipe_created_items():
    """Processing items for pipe_created category"""
    return [
        # Add ActionType condition for pipe_created events
        # This is needed because DeviceEvents table contains many ActionTypes
        ProcessingItem(
            identifier="microsoft_xdr_pipe_created_actiontype",
            transformation=AddConditionTransformation({"ActionType": "NamedPipeEvent"}),
            rule_conditions=[LogsourceCondition(category="pipe_created")],
        ),
        # Transform PipeName field to use SanitizedPipeName for pipe_created
        # PipeName in AdditionalFields needs to be accessed via SanitizedPipeName column
        ProcessingItem(
            identifier="microsoft_xdr_pipe_created_pipename",
            transformation=PipeNameTransformation(),
            field_name_conditions=[IncludeFieldCondition(["PipeName"])],
            rule_conditions=[LogsourceCondition(category="pipe_created")],
        ),
    ]


def _create_driver_load_items():
    """Processing items for driver_load category"""
    return [
        # Add ActionType condition for driver_load events
        ProcessingItem(
            identifier="microsoft_xdr_driver_load_actiontype",
            transformation=AddConditionTransformation({"ActionType": "DriverLoad"}),
            rule_conditions=[LogsourceCondition(category="driver_load")],
        ),
        # Split ImageLoaded into FolderPath and FileName for driver_load
        ProcessingItem(
            identifier="microsoft_xdr_driver_load_image_loaded_split",
            transformation=SplitFilePathTransformation(),
            field_name_conditions=[IncludeFieldCondition(["ImageLoaded"])],
            rule_conditions=[LogsourceCondition(category="driver_load")],
        )
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

# Image -> OriginalFileName
def _create_image_to_original_filename_item():
    """
    Custom DetectionItemTransformation to map Image to Image OR OriginalFileName.
    This allows matching against the original filename even if the file was renamed.
    It extracts the filename from the Image path and uses it for OriginalFileName.
    """
    return ProcessingItem(
        identifier="microsoft_xdr_image_to_original_filename",
        transformation=ImageToOriginalFileNameTransformation(),
        field_name_conditions=[IncludeFieldCondition(["Image"])],
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


def _get_valid_fields(table_name):
    """Get valid fields for a given table name"""
    valid_fields = (
        list(MICROSOFT_XDR_SCHEMA.tables[table_name].fields.keys())
        + list(MICROSOFT_XDR_FIELD_MAPPINGS.table_mappings.get(table_name, {}).keys())
        + list(MICROSOFT_XDR_FIELD_MAPPINGS.generic_mappings.keys())
        + ["Hashes"]
    )

    # Add SanitizedPipeName for DeviceEvents table (used by pipe_created category)
    if table_name == "DeviceEvents":
        valid_fields.append("SanitizedPipeName")

    return valid_fields

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
    transform_parent_image: Optional[bool] = True,
    transform_image_to_original_file_name: Optional[bool] = False,
    query_table: Optional[str] = None,
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
    Defaults to False
    :type transform_parent_image: Optional[bool]
    :param transform_image_to_original_file_name: If True, the Image field will be mapped to Image OR OriginalFileName.
    This allows matching against the original filename even if the file was renamed.
    Defaults to True
    :type transform_image_to_original_file_name: Optional[bool]

    :return: ProcessingPipeline for Microsoft 365 Defender Backend
    :rtype: ProcessingPipeline
    """

    pipeline_items = [
        _create_set_query_table_item(query_table),
        _create_drop_eventid_item(),
        _create_fieldmappings_item(),
        _create_generic_field_mappings_item(),
        *_create_replacement_items(),
        *_create_remote_thread_items(),
        *_create_pipe_created_items(),
        *_create_driver_load_items(),
        *_create_rule_error_items(),
        *_create_field_error_items(),
    ]

    if transform_parent_image:
        pipeline_items[4:4] = _create_parent_image_items()

    if transform_image_to_original_file_name:
        # Insert before field mappings (index 2) so that OriginalFileName can be mapped if needed
        pipeline_items.insert(2, _create_image_to_original_filename_item())


    return ProcessingPipeline(
        name="Generic Log Sources to Windows XDR tables and fields",
        priority=10,
        items=pipeline_items,
        allowed_backends=frozenset(["kusto"]),
        postprocessing_items=[create_prepend_query_table_item(), create_add_pipe_name_extend_item()],  # type: ignore
    )
