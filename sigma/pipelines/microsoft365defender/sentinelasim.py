from typing import Union, Optional, Iterable
from collections import defaultdict

from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.common import (logsource_windows_process_creation, logsource_windows_image_load,
                                    logsource_windows_file_event, logsource_windows_file_delete,
                                    logsource_windows_file_change, logsource_windows_file_access,
                                    logsource_windows_file_rename, logsource_windows_registry_set,
                                    logsource_windows_registry_add, logsource_windows_registry_delete,
                                    logsource_windows_registry_event, logsource_windows_network_connection)
from sigma.processing.transformations import (FieldMappingTransformation, RuleFailureTransformation,
                                            ReplaceStringTransformation, SetStateTransformation,
                                            DetectionItemTransformation, ValueTransformation,
                                            DetectionItemFailureTransformation, DropDetectionItemTransformation)
from sigma.processing.conditions import (IncludeFieldCondition, ExcludeFieldCondition,
                                        DetectionItemProcessingItemAppliedCondition, LogsourceCondition)
from sigma.conditions import ConditionOR
from sigma.types import SigmaString, SigmaType
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.rule import SigmaDetectionItem, SigmaDetection

from .microsoft365defender import (
    SplitDomainUserTransformation,
    HashesValuesTransformation,
    RegistryActionTypeValueTransformation,
    ParentImageValueTransformation,
    InvalidFieldTransformation,
)

process_events_table = 'imProcessCreate'
registry_events_table = 'imRegistry'
file_events_table = 'imFileEvent'

# FIELD MAPPINGS
## Field mappings from Sysmon (where applicable) fields to Advanced Hunting Query fields based on schema in tables
## See: https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-schema-tables?view=o365-worldwide#learn-the-schema-tables
query_table_field_mappings = {
    process_events_table: {  # process_creation, Sysmon EventID 1 -> DeviceProcessEvents table
        'ProcessGuid': 'TargetProcessGuid',
        'ProcessId': 'TargetProcessId',
        'Image': 'TargetProcessName',
        'FileVersion': 'TargetProcessFileVersion',
        'Description': 'TargetProcessFileDescription',
        'Product': 'TargetProcessFileProduct',
        'Company': 'TargetProcessFileCompany',
        'OriginalFileName': 'TargetProcessFilename',
        'CommandLine': 'TargetProcessCommandLine',
        'CurrentDirectory': 'TargetProcessCurrentDirectory',
        'User': 'TargetUsername',
        'LogonGuid': 'TargetUserSessionGuid',
        'LogonId': 'TargetUsername',
        'TerminalSessionId': 'TargetUserSessionId',
        'IntegrityLevel': 'TargetProcessIntegrityLevel',
        'sha1': 'TargetProcessSHA1',
        'sha256': 'TargetProcessSHA256',
        'md5': 'TargetProcessMD5',
        'ParentProcessGuid': 'ActingProcessGuid',
        'ParentProcessId': 'ActingProcessId',
        'ParentImage': 'ActingProcessName',
        'ParentCommandLine': 'ActingProcessCommandLine',
        'ParentUser': 'ActorUsername',
        'ProcessVersionInfoOriginalFileName':'TargetProcessFileVersion',
        'ProcessVersionInfoFileDescription':'TargetProcessFileDescription',
        'ProcessIntegrityLevel': 'TargetProcessIntegrityLevel',
        'InitiatingProcessFolderPath': 'ActingProcessName',
        'InitiatingProcessCommandLine': 'ActingProcessCommandLine',
    },
    'DeviceImageLoadEvents': {
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',  # File path of the process that loaded the image
        'ImageLoaded': 'FolderPath',
        'FileVersion': 'InitiatingProcessVersionInfoProductVersion',
        'Description': 'InitiatingProcessVersionInfoFileDescription',
        'Product': 'InitiatingProcessVersionInfoProductName',
        'Company': 'InitiatingProcessVersionInfoCompanyName',
        'OriginalFileName': 'InitiatingProcessVersionInfoOriginalFileName',
        # 'Hashes': ?,
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5',
        # 'Signed': ?
        # 'Signature': ?
        # 'SignatureStatus': ?
        'User': 'InitiatingProcessAccountName'
    },
    file_events_table: {  # file_*, Sysmon EventID 11 (create), 23 (delete) -> DeviceFileEvents table
        'ProcessGuid': 'ActingProcessGuid',
        'ProcessId': 'ActingProcessId',
        'Image': 'ActingProcessName',
        'TargetFilename': 'TargetFileName',
        'CreationUtcTime': 'TargetFileCreationTime',
        'User': 'ActorUsername',
        # 'Hashes': ?,
        # 'sha1': 'SHA1',
        # 'sha256': 'SHA256',
        # 'md5': 'MD5',
    },
    'DeviceNetworkEvents': {  # network_connection, Sysmon EventID 3 -> DeviceNetworkEvents table
        # 'ProcessGuid': ?,
        'ProcessId': 'InitiatingProcessId',
        'Image': 'InitiatingProcessFolderPath',
        'User': 'InitiatingProcessAccountName',
        'Protocol': 'Protocol',
        # 'Initiated': ?,
        # 'SourceIsIpv6': ?,
        'SourceIp': 'LocalIP',
        'SourceHostname': 'DeviceName',
        'SourcePort': 'LocalPort',
        # 'SourcePortName': ?,
        # 'DestinationIsIpv6': ?,
        'DestinationIp': 'RemoteIP',
        'DestinationHostname': 'RemoteUrl',
        'DestinationPort': 'RemotePort',
        # 'DestinationPortName': ?,
    },
    registry_events_table: {
        # registry_*, Sysmon EventID 12 (create/delete), 13 (value set), 14 (key/value rename) -> DeviceRegistryEvents table,
        'EventType': 'EventType',
        'ProcessGuid': 'ActingProcessGuid',
        'ProcessId': 'ActingProcessId',
        'Image': 'ActingProcessName',
        'TargetObject': 'RegistryKey',
        # 'NewName': ?
        'Details': 'RegistryValueData',
        'User': 'ActorUsername'
    }
}

## Generic catch-all field mappings for sysmon -> microsoft 365 defender fields that appear in most tables and
## haven't been mapped already
generic_field_mappings = {
    'EventType': 'EventType',
    'User': 'TargetUsername',
    'CommandLine': 'TargetProcessCommandLine',
    'Image': 'TargetProcessName',
    'SourceImage': 'TargetProcessName',
    'ProcessId': 'TargetProcessId',
    'md5': 'TargetProcessMD5',
    #'sha1': 'InitiatingProcessSHA1',
    'sha256': 'TargetProcessSHA256',
    'ParentProcessId': 'ActingProcessId',
    'ParentCommandLine': 'ActingProcessCommandLine',
    'Company': 'TargetProcessFileCompany',
    'Description': 'TargetProcessFileDescription',
    'OriginalFileName': 'TargetProcessName',
    'Product': 'TargetProcessFileProduct',
    'Timestamp': 'TimeGenerated',
    'FolderPath': 'TargetProcessName',
    'ProcessCommandLine': 'TargetProcessCommandLine',
}

# VALID FIELDS PER QUERY TABLE
## Will Implement field checking later once issue with removing fields is figured out, for now it fails the pipeline
## dict of {'table_name': [list, of, valid_fields]} for each table
valid_fields_per_table = {
    process_events_table: [
        "TimeGenerated",
        "TargetProcessGuid",
        "TargetProcessId",
        "TargetProcessName",
        "TargetProcessFileVersion",
        "TargetProcessFileDescription",
        "TargetProcessFileProduct",
        "CommandLine",
        "User",
        "TargetUserSessionGuid",
        "TargetProcessIntegrityLevel",
        "ActingProcessGuid",
        "ActingProcessId",
        "ActingProcessName",
        "ActingProcessCommandLine",
        "ActorUsername",
        "TargetProcessSHA256",
        "TargetProcessIMPHASH",
        "TargetProcessMD5",
        "EventType",
        "EventStartTime",
        "EventEndTime",
        "EventCount",
        "EventVendor",
        "EventSchemaVersion",
        "EventSchema",
        "EventProduct",
        "EventResult",
        "DvcOs",
        "TargetUserSessionId",
        "TargetUsernameType",
        "TargetUsername",
        "TargetProcessCommandLine",
        "TargetProcessCurrentDirectory",
        "ActorUsernameType",
        "EventOriginalType",
        "Process",
        "Dvc",
        "Hash",
        "DvcHostname",
        "EventSourceName",
        "TargetProcessFileCompany",
        "TargetProcessFilename",
        "HashType",
        "Channel",
        "Task",
        "SourceComputerId",
        "EventOriginId",
        "TimeCollected"
    ],
    'DeviceImageLoadEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                            'SHA256', 'MD5', 'FileSize', 'InitiatingProcessAccountDomain',
                            'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                            'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId',
                            'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                            'InitiatingProcessSHA1', 'InitiatingProcessSHA256', 'InitiatingProcessMD5',
                            'InitiatingProcessFileName', 'InitiatingProcessFileSize',
                            'InitiatingProcessVersionInfoCompanyName', 'InitiatingProcessVersionInfoProductName',
                            'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                            'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime', 'ReportId',
                            'AppGuardContainerId'],
    file_events_table: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'FileName', 'FolderPath', 'SHA1',
                        'SHA256', 'MD5', 'FileOriginUrl', 'FileOriginReferrerUrl', 'FileOriginIP',
                        'PreviousFolderPath', 'PreviousFileName', 'FileSize', 'InitiatingProcessAccountDomain',
                        'InitiatingProcessAccountName', 'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                        'InitiatingProcessAccountObjectId', 'InitiatingProcessMD5', 'InitiatingProcessSHA1',
                        'InitiatingProcessSHA256', 'InitiatingProcessFolderPath', 'InitiatingProcessFileName',
                        'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                        'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                        'InitiatingProcessVersionInfoInternalFileName', 'InitiatingProcessVersionInfoOriginalFileName',
                        'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                        'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                        'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation',
                        'InitiatingProcessParentId', 'InitiatingProcessParentFileName',
                        'InitiatingProcessParentCreationTime', 'RequestProtocol', 'RequestSourceIP',
                        'RequestSourcePort', 'RequestAccountName', 'RequestAccountDomain', 'RequestAccountSid',
                        'ShareName', 'InitiatingProcessFileSize', 'SensitivityLabel', 'SensitivitySubLabel',
                        'IsAzureInfoProtectionApplied', 'ReportId', 'AppGuardContainerId', 'AdditionalFields'],
    registry_events_table: ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RegistryKey', 'RegistryValueType',
                            'RegistryValueName', 'RegistryValueData', 'PreviousRegistryKey',
                            'PreviousRegistryValueName', 'PreviousRegistryValueData', 'InitiatingProcessAccountDomain',
                            'InitiatingProcessAccountName', 'InitiatingProcessAccountSid',
                            'InitiatingProcessAccountUpn', 'InitiatingProcessAccountObjectId', 'InitiatingProcessSHA1',
                            'InitiatingProcessSHA256', 'InitiatingProcessMD5', 'InitiatingProcessFileName',
                            'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                            'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath', 'InitiatingProcessParentId',
                            'InitiatingProcessParentFileName', 'InitiatingProcessParentCreationTime',
                            'InitiatingProcessIntegrityLevel', 'InitiatingProcessTokenElevation', 'ReportId',
                            'AppGuardContainerId'],
    'DeviceNetworkEvents': ['Timestamp', 'DeviceId', 'DeviceName', 'ActionType', 'RemoteIP', 'RemotePort', 'RemoteUrl',
                            'LocalIP', 'LocalPort', 'Protocol', 'LocalIPType', 'RemoteIPType', 'InitiatingProcessSHA1',
                            'InitiatingProcessSHA256', 'InitiatingProcessMD5', 'InitiatingProcessFileName',
                            'InitiatingProcessFileSize', 'InitiatingProcessVersionInfoCompanyName',
                            'InitiatingProcessVersionInfoProductName', 'InitiatingProcessVersionInfoProductVersion',
                            'InitiatingProcessVersionInfoInternalFileName',
                            'InitiatingProcessVersionInfoOriginalFileName',
                            'InitiatingProcessVersionInfoFileDescription', 'InitiatingProcessId',
                            'InitiatingProcessCommandLine', 'InitiatingProcessCreationTime',
                            'InitiatingProcessFolderPath', 'InitiatingProcessParentFileName',
                            'InitiatingProcessParentId', 'InitiatingProcessParentCreationTime',
                            'InitiatingProcessAccountDomain', 'InitiatingProcessAccountName',
                            'InitiatingProcessAccountSid', 'InitiatingProcessAccountUpn',
                            'InitiatingProcessAccountObjectId', 'InitiatingProcessIntegrityLevel',
                            'InitiatingProcessTokenElevation', 'ReportId', 'AppGuardContainerId', 'AdditionalFields']}

# Mapping from ParentImage to InitiatingProcessParentFileName. Must be used alongside of ParentImageValueTransformation
parent_image_field_mapping = {'ParentImage': 'InitiatingProcessParentFileName'}

# OTHER MAPPINGS
## useful for creating ProcessingItems() with list comprehension

## Query Table names -> rule categories
table_to_category_mappings = {
    process_events_table: ['process_creation'],
    'DeviceImageLoadEvents': ['image_load'],
    file_events_table: ['file_access', 'file_change', 'file_delete', 'file_event', 'file_rename'],
    registry_events_table: ['registry_add', 'registry_delete', 'registry_event', 'registry_set'],
    'DeviceNetworkEvents': ['network_connection']
}

## rule categories -> RuleConditions
category_to_conditions_mappings = {
    'process_creation': logsource_windows_process_creation(),
    'image_load': logsource_windows_image_load(),
    'file_access': logsource_windows_file_access(),
    'file_change': logsource_windows_file_change(),
    'file_delete': logsource_windows_file_delete(),
    'file_event': logsource_windows_file_event(),
    'file_rename': logsource_windows_file_rename(),
    'registry_add': logsource_windows_registry_add(),
    'registry_delete': logsource_windows_registry_delete(),
    'registry_event': logsource_windows_registry_event(),
    'registry_set': logsource_windows_registry_set(),
    'network_connection': logsource_windows_network_connection()
}

# PROCESSING_ITEMS()
## ProcessingItems to set state key 'query_table' to use in backend
## i.e. $QueryTable$ | $rest_of_query$
query_table_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_365_defender_set_query_table_{table_name}",
        transformation=SetStateTransformation("query_table", table_name),
        rule_conditions=[
            category_to_conditions_mappings[rule_category] for rule_category in rule_categories
        ],
        rule_condition_linking=any,
    )
    for table_name, rule_categories in table_to_category_mappings.items()
]

## Fieldmappings
fieldmappings_proc_items = [
    ProcessingItem(
        identifier=f"microsoft_365_defender_fieldmappings_{table_name}",
        transformation=FieldMappingTransformation(query_table_field_mappings[table_name]),
        rule_conditions=[
            category_to_conditions_mappings[rule_category] for rule_category in rule_categories
        ],
        rule_condition_linking=any,
    )
    for table_name, rule_categories in table_to_category_mappings.items()
]

## Generic Fielp Mappings, keep this last
## Exclude any fields already mapped. For example, if process_creation events ProcessId has already
## been mapped to the same field name (ProcessId), we don't to remap it to InitiatingProcessId
generic_field_mappings_proc_item = [ProcessingItem(
    identifier="microsoft_365_defender_fieldmappings_generic",
    transformation=FieldMappingTransformation(
        generic_field_mappings
    ),
    detection_item_conditions=[
        DetectionItemProcessingItemAppliedCondition(f"microsoft_365_defender_fieldmappings_{table_name}")
        for table_name in table_to_category_mappings.keys()
    ],
    detection_item_condition_linking=any,
    detection_item_condition_negation=True,
)
]

## Field Value Replacements ProcessingItems
replacement_proc_items = [
    # Sysmon uses abbreviations in RegistryKey values, replace with full key names as the DeviceRegistryEvents schema
    # expects them to be
    # Note: Ensure this comes AFTER field mapping renames, as we're specifying DeviceRegistryEvent fields
    #
    # Do this one first, or else the HKLM only one will replace HKLM and mess up the regex
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_currentcontrolset",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM\\SYSTEM\\CurrentControlSet)",
                                                replacement=r"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet001"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hklm",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKLM)",
                                                replacement=r"HKEY_LOCAL_MACHINE"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hku",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKU)",
                                                replacement=r"HKEY_USERS"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_key_replace_hkcr",
        transformation=ReplaceStringTransformation(regex=r"(?i)(^HKCR)",
                                                replacement=r"HKEY_LOCAL_MACHINE\\CLASSES"),
        field_name_conditions=[IncludeFieldCondition(['RegistryKey', 'PreviousRegistryKey'])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_registry_actiontype_value",
        transformation=RegistryActionTypeValueTransformation(),
        field_name_conditions=[IncludeFieldCondition(['ActionType'])]
    ),
    # Extract Domain from Username fields
    ProcessingItem(
        identifier="microsoft_365_defender_domain_username_extract",
        transformation=SplitDomainUserTransformation(),
        field_name_conditions=[IncludeFieldCondition(["AccountName", "InitiatingProcessAccountName"])]
    ),
    ProcessingItem(
        identifier="microsoft_365_defender_hashes_field_values",
        transformation=HashesValuesTransformation(),
        field_name_conditions=[IncludeFieldCondition(['Hashes'])]
    ),
    # Processing item to essentially ignore initiated field
    ProcessingItem(
        identifier="microsoft_365_defender_network_initiated_field",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(['Initiated'])],
        rule_conditions=[LogsourceCondition(category='network_connection')],
    )
]

# ParentImage -> InitiatingProcessParentFileName
parent_image_proc_items = [
    # First apply fieldmapping from ParentImage to InitiatingProcessParentFileName for non process-creation rules
    ProcessingItem(
        identifier="microsoft_365_defender_parent_image_fieldmapping",
        transformation=FieldMappingTransformation(parent_image_field_mapping),
        rule_conditions=[
            # Exclude process_creation events, there's direct field mapping in this schema table
            LogsourceCondition(category='process_creation')
        ],
        rule_condition_negation=True
    ),
    # Second, extract the parent process name from the full path
    ProcessingItem(
        identifier="microsoft_365_defender_parent_image_name_value",
        transformation=ParentImageValueTransformation(),
        field_name_conditions=[
            IncludeFieldCondition(["InitiatingProcessParentFileName"]),
        ],
        rule_conditions=[
            # Exclude process_creation events, there's direct field mapping in this schema table
            LogsourceCondition(category='process_creation')
        ],
        rule_condition_negation=True
    )

]

## Exceptions/Errors ProcessingItems
rule_error_proc_items = [
    # Category Not Supported
    ProcessingItem(
        identifier="microsoft_365_defender_unsupported_rule_category",
        rule_condition_linking=any,
        transformation=RuleFailureTransformation(
            "Rule category not yet supported by the Microsoft 365 Defender Sigma backend."
        ),
        rule_condition_negation=True,
        rule_conditions=[x for x in category_to_conditions_mappings.values()],
    )]

field_error_proc_items = [
    # Invalid fields per category
    ProcessingItem(
        identifier=f"microsoft_365_defender_unsupported_fields_{table_name}",
        transformation=InvalidFieldTransformation(
            f"Please use valid fields for the {table_name} table, or the following fields that have keymappings in this "
            f"pipeline:\n"
            # Combine field mappings for table and generic field mappings dicts, get the unique keys, add the Hashes field, sort it
            f"{', '.join(sorted(set({**query_table_field_mappings[table_name], **generic_field_mappings}.keys()).union({'Hashes'})))}"
        ),
        field_name_conditions=[
            ExcludeFieldCondition(fields=table_fields + list(generic_field_mappings.keys()) + ['Hashes'])],
        rule_conditions=[
            category_to_conditions_mappings[rule_category]
            for rule_category in table_to_category_mappings[table_name]
        ],
        rule_condition_linking=any,
    )
    for table_name, table_fields in valid_fields_per_table.items()
]


def sentinel_asim_pipeline(transform_parent_image: Optional[bool] = True) -> ProcessingPipeline:
    """Pipeline for transformations for SigmaRules to use with the Sentinel ASIM Functions

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
        *query_table_proc_items,
        *fieldmappings_proc_items,
        *generic_field_mappings_proc_item,
        *replacement_proc_items,
        *rule_error_proc_items,
        *field_error_proc_items,
    ]

    if transform_parent_image:
        pipeline_items[4:4] = parent_image_proc_items

    return ProcessingPipeline(
        name="Generic Log Sources to Windows 365 ASIM Transformation",
        priority=10,
        items=pipeline_items,
    )
