from sigma.pipelines.common import (
    logsource_windows_file_access,
    logsource_windows_file_change,
    logsource_windows_file_delete,
    logsource_windows_file_event,
    logsource_windows_file_rename,
    logsource_windows_image_load,
    logsource_windows_network_connection,
    logsource_windows_process_creation,
    logsource_windows_registry_add,
    logsource_windows_registry_delete,
    logsource_windows_registry_event,
    logsource_windows_registry_set,
)
from sigma.pipelines.kusto_common.schema import FieldMappings

## Rule Categories -> Query Table Names
CATEGORY_TO_TABLE_MAPPINGS = {
    "process_creation": "DeviceProcessEvents",
    "image_load": "DeviceImageLoadEvents",
    "file_access": "DeviceFileEvents",
    "file_change": "DeviceFileEvents",
    "file_delete": "DeviceFileEvents",
    "file_event": "DeviceFileEvents",
    "file_rename": "DeviceFileEvents",
    "registry_add": "DeviceRegistryEvents",
    "registry_delete": "DeviceRegistryEvents",
    "registry_event": "DeviceRegistryEvents",
    "registry_set": "DeviceRegistryEvents",
    "network_connection": "DeviceNetworkEvents",
}

EVENTID_CATEGORY_TO_TABLE_MAPPINGS = {
    "process": "DeviceProcessEvents",
    "logon": "DeviceLogonEvents",
    "registry": "DeviceRegistryEvents",
    "file": "DeviceFileEvents",
    "network": "DeviceNetworkEvents",
    "image_load": "DeviceImageLoadEvents",
    "pipe": "DeviceEvents",
    "wmi": "DeviceEvents",
}

## Rule Categories -> RuleConditions
CATEGORY_TO_CONDITIONS_MAPPINGS = {
    "process_creation": logsource_windows_process_creation(),
    "image_load": logsource_windows_image_load(),
    "file_access": logsource_windows_file_access(),
    "file_change": logsource_windows_file_change(),
    "file_delete": logsource_windows_file_delete(),
    "file_event": logsource_windows_file_event(),
    "file_rename": logsource_windows_file_rename(),
    "registry_add": logsource_windows_registry_add(),
    "registry_delete": logsource_windows_registry_delete(),
    "registry_event": logsource_windows_registry_event(),
    "registry_set": logsource_windows_registry_set(),
    "network_connection": logsource_windows_network_connection(),
}


class MicrosoftXDRFieldMappings(FieldMappings):
    pass


MICROSOFT_XDR_FIELD_MAPPINGS = MicrosoftXDRFieldMappings(
    table_mappings={
        "DeviceProcessEvents": {  # process_creation, Sysmon EventID 1 -> DeviceProcessEvents table
            # ProcessGuid: ?,
            "ProcessId": "ProcessId",
            "Image": "FolderPath",
            "FileVersion": "ProcessVersionInfoProductVersion",
            "Description": "ProcessVersionInfoFileDescription",
            "Product": "ProcessVersionInfoProductName",
            "Company": "ProcessVersionInfoCompanyName",
            "OriginalFileName": "ProcessVersionInfoOriginalFileName",
            "CommandLine": "ProcessCommandLine",
            # CurrentDirectory: ?
            "User": "AccountName",
            "ComputerName": "DeviceName",
            # LogonGuid: ?
            "LogonId": "LogonId",
            # TerminalSessionId: ?
            "IntegrityLevel": "ProcessIntegrityLevel",
            "sha1": "SHA1",
            "sha256": "SHA256",
            "md5": "MD5",
            # 'ParentProcessGuid': ?,
            "ParentProcessId": "InitiatingProcessId",
            "ParentImage": "InitiatingProcessFolderPath",
            "ParentCommandLine": "InitiatingProcessCommandLine",
            "ParentUser": "InitiatingProcessAccountName",
            "GrandParentImage": "InitiatingProcessParentFileName",
        },
        "DeviceImageLoadEvents": {
            # 'ProcessGuid': ?,
            "ProcessId": "InitiatingProcessId",
            "Image": "InitiatingProcessFolderPath",  # File path of the process that loaded the image
            "ImageLoaded": "FolderPath",
            "FileVersion": "InitiatingProcessVersionInfoProductVersion",
            "Description": "InitiatingProcessVersionInfoFileDescription",
            "Product": "InitiatingProcessVersionInfoProductName",
            "Company": "InitiatingProcessVersionInfoCompanyName",
            "OriginalFileName": "InitiatingProcessVersionInfoOriginalFileName",
            # 'Hashes': ?,
            "sha1": "SHA1",
            "sha256": "SHA256",
            "md5": "MD5",
            # 'Signed': ?
            # 'Signature': ?
            # 'SignatureStatus': ?
            "User": "InitiatingProcessAccountName",
            "ComputerName": "DeviceName",
        },
        "DeviceFileEvents": {  # file_*, Sysmon EventID 11 (create), 23 (delete) -> DeviceFileEvents table
            # 'ProcessGuid': ?,
            "ProcessId": "InitiatingProcessId",
            "Image": "InitiatingProcessFolderPath",
            "TargetFilename": "FolderPath",
            # 'CreationUtcTime': 'Timestamp',
            "User": "RequestAccountName",
            "ComputerName": "DeviceName",
            # 'Hashes': ?,
            "sha1": "SHA1",
            "sha256": "SHA256",
            "md5": "MD5",
            "ObjectName": "FolderPath",
            "IntegrityLevel": "InitiatingProcessIntegrityLevel",
        },
        "DeviceNetworkEvents": {  # network_connection, Sysmon EventID 3 -> DeviceNetworkEvents table
            # 'ProcessGuid': ?,
            "ProcessId": "InitiatingProcessId",
            "Image": "InitiatingProcessFolderPath",
            "User": "InitiatingProcessAccountName",
            "ComputerName": "DeviceName",
            "Protocol": "Protocol",
            # 'Initiated': ?,
            # 'SourceIsIpv6': ?,
            "SourceIp": "LocalIP",
            "SourceHostname": "DeviceName",
            "SourcePort": "LocalPort",
            # 'SourcePortName': ?,
            # 'DestinationIsIpv6': ?,
            "DestinationIp": "RemoteIP",
            "DestinationHostname": "RemoteUrl",
            "DestinationPort": "RemotePort",
            # 'DestinationPortName': ?,
        },
        "DeviceRegistryEvents": {
            # registry_*, Sysmon EventID 12 (create/delete), 13 (value set), 14 (key/value rename) -> DeviceRegistryEvents table,
            "EventType": "ActionType",
            # 'ProcessGuid': ?,
            "ProcessId": "InitiatingProcessId",
            "Image": "InitiatingProcessFolderPath",
            "TargetObject": "RegistryKey",
            # 'NewName': ?
            "Details": "RegistryValueData",
            "User": "InitiatingProcessAccountName",
            "ComputerName": "DeviceName",
            "ObjectName": "RegistryKey",
        },
    },
    generic_mappings={
        "EventType": "ActionType",
        "User": "InitiatingProcessAccountName",
        "ComputerName": "DeviceName",
        "CommandLine": "InitiatingProcessCommandLine",
        "Image": "InitiatingProcessFolderPath",
        "ProcessName": "InitiatingProcessFolderPath",
        "SourceImage": "InitiatingProcessFolderPath",
        "ProcessId": "InitiatingProcessId",
        "md5": "InitiatingProcessMD5",
        "sha1": "InitiatingProcessSHA1",
        "sha256": "InitiatingProcessSHA256",
        "ParentProcessId": "InitiatingProcessParentId",
        "ParentCommandLine": "InitiatingProcessParentCommandLine",
        "Company": "InitiatingProcessVersionInfoCompanyName",
        "Description": "InitiatingProcessVersionInfoFileDescription",
        "OriginalFileName": "InitiatingProcessVersionInfoOriginalFileName",
        "Product": "InitiatingProcessVersionInfoProductName",
    },
)
