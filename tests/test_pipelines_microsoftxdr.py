import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.kusto_common.errors import InvalidHashAlgorithmError
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.rule import SigmaRule


@pytest.fixture
def xdr_backend():
    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline())


def test_microsoft_xdr_pipeline_alias():
    assert microsoft_xdr_pipeline() == microsoft_365_defender_pipeline()


def test_microsoft_xdr_username_transformation(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel1:
                CommandLine: command1
                AccountName: username1
            sel2:
                CommandLine: command2
                AccountName: domain2\\username2
            sel3:
                CommandLine: command3
                InitiatingProcessAccountName:
                    - username3
                    - domain4\\username4
            sel4:
                AccountName: username5
            condition: any of sel*
    """
    expected_result = [
        "DeviceProcessEvents\n| "
        'where (ProcessCommandLine =~ "command1" and AccountName =~ "username1") or '
        '(ProcessCommandLine =~ "command2" and (AccountName =~ "username2" and AccountDomain =~ "domain2")) or '
        '(ProcessCommandLine =~ "command3" and (InitiatingProcessAccountName =~ "username3" or '
        '(InitiatingProcessAccountName =~ "username4" and InitiatingProcessAccountDomain =~ "domain4"))) or '
        'AccountName =~ "username5"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_hashes_values_transformation(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel1:
                Hashes:
                    - md5|e708864855f3bb69c4d9a213b9108b9f
                    - sha1|00ea1da4192a2030f9ae023de3b3143ed647bbab
                    - sha256|6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
            sel2:
                Hashes:
                    - 0b49939d6415354c950b142a0b1e696a
                    - 4b2b79b6f371ca18f1216461cffeaddf6848a50e
                    - 8f16f88cfa1cf0d17c75403aa9614d806ebc00419763e0ecac3860decbcd9988
                    - invalidhashvalue
            condition: any of sel*
    """
    expected_result = [
        "DeviceProcessEvents\n"
        '| where (MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" or SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" '
        'or SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf") or '
        '(MD5 =~ "0b49939d6415354c950b142a0b1e696a" or SHA1 =~ "4b2b79b6f371ca18f1216461cffeaddf6848a50e" or '
        'SHA256 =~ "8f16f88cfa1cf0d17c75403aa9614d806ebc00419763e0ecac3860decbcd9988")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_process_creation_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceProcessEvents\n| where ProcessCommandLine =~ "val1" and FolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_image_load_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ImageLoaded: val1
                sha1: val2
            condition: sel
    """
    expected_result = ['DeviceImageLoadEvents\n| where FolderPath =~ "val1" and SHA1 =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_access_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_access
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_change_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_delete_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_delete
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_event_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_rename_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_rename
            product: windows
        detection:
            sel:
                TargetFilename: val1
                Image: val2
            condition: sel
    """
    expected_result = ['DeviceFileEvents\n| where FolderPath =~ "val1" and InitiatingProcessFolderPath =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_add_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_delete_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_delete
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_event_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_set_simple(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                Image: val1
                TargetObject: val2
            condition: sel
    """
    expected_result = ['DeviceRegistryEvents\n| where InitiatingProcessFolderPath =~ "val1" and RegistryKey =~ "val2"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_process_creation_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: C:\\Path\\to\\notmalware.exe
                FileVersion: 1
                Description: A Description
                Product: pySigma
                Company: AttackIQ
                OriginalFileName: malware.exe
                ProcessId: 2
                CommandLine: definitely not malware
                User: heyitsmeyourbrother
                IntegrityLevel: 1
                sha1: a123123123
                sha256: a123123123
                md5: a123123123
                ParentProcessId: 1
                ParentImage: C:\\Windows\\Temp\\freemoney.pdf
                ParentCommandLine: freemoney.pdf test exe please ignore
                ParentUser: heyitsmeyourparent
            condition: sel
    """
    expected_result = [
        "DeviceProcessEvents\n| "
        'where FolderPath =~ "C:\\\\Path\\\\to\\\\notmalware.exe" and '
        "ProcessVersionInfoProductVersion == 1 and "
        'ProcessVersionInfoFileDescription =~ "A Description" and '
        'ProcessVersionInfoProductName =~ "pySigma" and '
        'ProcessVersionInfoCompanyName =~ "AttackIQ" and '
        'ProcessVersionInfoOriginalFileName =~ "malware.exe" and '
        "ProcessId == 2 and "
        'ProcessCommandLine =~ "definitely not malware" and '
        'AccountName =~ "heyitsmeyourbrother" and '
        "ProcessIntegrityLevel == 1 and "
        'SHA1 =~ "a123123123" and '
        'SHA256 =~ "a123123123" and '
        'MD5 =~ "a123123123" and '
        "InitiatingProcessId == 1 and "
        'InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\Temp\\\\freemoney.pdf" and '
        'InitiatingProcessCommandLine =~ "freemoney.pdf test exe please ignore" and '
        'InitiatingProcessAccountName =~ "heyitsmeyourparent"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_image_load_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Temp\\notmalware.exe
                ImageLoaded: C:\\Temp\\definitelynotmalware.exe
                FileVersion: 1
                Description: A Description
                Product: A Product
                Company: AttackIQ
                OriginalFileName: freemoney.pdf.exe
                md5: e708864855f3bb69c4d9a213b9108b9f
                sha1: 00ea1da4192a2030f9ae023de3b3143ed647bbab
                sha256: 6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
                User: username
            condition: sel
    """
    expected_result = [
        "DeviceImageLoadEvents\n| "
        'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notmalware.exe" and '
        'FolderPath =~ "C:\\\\Temp\\\\definitelynotmalware.exe" and InitiatingProcessVersionInfoProductVersion == 1 '
        'and InitiatingProcessVersionInfoFileDescription =~ "A Description" and '
        'InitiatingProcessVersionInfoProductName =~ "A Product" and '
        'InitiatingProcessVersionInfoCompanyName =~ "AttackIQ" and '
        'InitiatingProcessVersionInfoOriginalFileName =~ "freemoney.pdf.exe" and '
        'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
        'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf" and '
        'InitiatingProcessAccountName =~ "username"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_file_event_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Path\\To\\process.exe
                TargetFilename: C:\\Temp\\passwords.txt
                User: username
                md5: e708864855f3bb69c4d9a213b9108b9f
                sha1: 00ea1da4192a2030f9ae023de3b3143ed647bbab
                sha256: 6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf
            condition: sel
    """
    expected_result = [
        "DeviceFileEvents\n| "
        'where InitiatingProcessId == 1 and InitiatingProcessFolderPath =~ "C:\\\\Path\\\\To\\\\process.exe" and '
        'FolderPath =~ "C:\\\\Temp\\\\passwords.txt" and RequestAccountName =~ "username" and '
        'MD5 =~ "e708864855f3bb69c4d9a213b9108b9f" and SHA1 =~ "00ea1da4192a2030f9ae023de3b3143ed647bbab" and '
        'SHA256 =~ "6bbb0da1891646e58eb3e6a63af3a6fc3c8eb5a0d44824cba581d2e14a0450cf"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_registry_event_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                EventType: CreateKey
                ProcessId: 1
                Image: C:\\Temp\\reg.exe
                TargetObject: HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\services\\TrustedInstaller
                Details: attackiq
                User: username
            condition: sel
    """
    expected_result = [
        "DeviceRegistryEvents\n| "
        'where ActionType =~ "RegistryKeyCreated" and InitiatingProcessId == 1 and '
        'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\reg.exe" and '
        'RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\ControlSet001\\\\services\\\\TrustedInstaller" and '
        'RegistryValueData =~ "attackiq" and InitiatingProcessAccountName =~ "username"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_network_connection_field_mapping(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                ProcessId: 1
                Image: C:\\Temp\\notcobaltstrike.exe
                User: admin
                Protocol: TCP
                SourceIp: 127.0.0.1
                SourcePort: 12345
                DestinationIp: 1.2.3.4
                DestinationPort: 50050
                DestinationHostname: notanatp.net
            condition: sel
    """
    expected_result = [
        "DeviceNetworkEvents\n| "
        "where InitiatingProcessId == 1 and "
        'InitiatingProcessFolderPath =~ "C:\\\\Temp\\\\notcobaltstrike.exe" and '
        'InitiatingProcessAccountName =~ "admin" and Protocol =~ "TCP" and LocalIP =~ "127.0.0.1" and '
        'LocalPort == 12345 and RemoteIP =~ "1.2.3.4" and RemotePort == 50050 and '
        'RemoteUrl =~ "notanatp.net"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_network_connection_cidr(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                SourceIp|cidr: '10.10.0.0/24'
                DestinationIp|cidr: '10.11.0.0/24'
            condition: sel
    """
    expected_result = [
        "DeviceNetworkEvents\n| "
        'where ipv4_is_in_range(LocalIP, "10.10.0.0/24") and ipv4_is_in_range(RemoteIP, "10.11.0.0/24")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_registrykey_replacements(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel1:
                RegistryKey: HKLM\\TestKey1
                PreviousRegistryKey: HKLM\\TestKey1
            sel2:
                RegistryKey: HKU\\TestKey2
                PreviousRegistryKey: HKU\\TestKey2
            sel3:
                RegistryKey: HKLM\\System\\CurrentControlSet\\TestKey3
                PreviousRegistryKey: HKLM\\System\\CurrentControlSet\\TestKey3
            sel4:
                RegistryKey: hkcr\\TestKey4
                PreviousRegistryKey: hkcr\\TestKey4
            condition: any of sel*
    """
    expected_result = [
        'DeviceRegistryEvents\n| where (RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1" and '
        'PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\TestKey1") or '
        '(RegistryKey =~ "HKEY_USERS\\\\TestKey2" and PreviousRegistryKey =~ "HKEY_USERS\\\\TestKey2") or '
        '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet001\\\\TestKey3") or '
        '(RegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4" and PreviousRegistryKey =~ "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\TestKey4")'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_registry_actiontype_replacements(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel1:
                ActionType: CreateKey
            sel2:
                ActionType: DeleteKey
            sel3:
                ActionType: SetValue
            sel4:
                ActionType: RenameKey
            condition: any of sel*
    """
    expected_result = [
        "DeviceRegistryEvents\n| "
        'where ActionType =~ "RegistryKeyCreated" or '
        '(ActionType in~ ("RegistryKeyDeleted", "RegistryValueDeleted")) or '
        'ActionType =~ "RegistryValueSet" or '
        '(ActionType in~ ("RegistryValueSet", "RegistryKeyCreated"))'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_valid_hash_in_list(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Hashes: 
                    - MD5=6444f8a34e99b8f7d9647de66aabe516
                    - IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f
                    - IMPHASH=1a6cca4d5460b1710a12dea39e4a592c
            condition: sel
    """
    expected_result = ["DeviceProcessEvents\n| " 'where MD5 =~ "6444f8a34e99b8f7d9647de66aabe516"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_generic_field(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                CommandLine: whoami
                ProcessId: 1  
            condition: any of sel*
    """
    expected_result = [
        "DeviceFileEvents\n| " 'where InitiatingProcessCommandLine =~ "whoami" and InitiatingProcessId == 1'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_parent_image(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                Image: C:\\Windows\\System32\\whoami.exe
                ParentImage: C:\\Windows\\System32\\cmd.exe  
            condition: any of sel*
    """
    expected_result = [
        "DeviceFileEvents\n| "
        'where InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\System32\\\\whoami.exe" and '
        'InitiatingProcessParentFileName =~ "cmd.exe"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_pipeline_parent_image_false(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel1:
                Image: C:\\Windows\\System32\\whoami.exe
                ParentImage: C:\\Windows\\System32\\cmd.exe  
            condition: any of sel*
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"
    ):
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(transform_parent_image=False)).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )


def test_microsoft_xdr_pipeline_unsupported_rule_type(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: invalid_category
            product: invalid_product
        detection:
            sel:
                field: whatever
            condition: sel
    """
    with pytest.raises(SigmaTransformationError, match="Unable to determine table name from rule. "):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_process_creation(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceProcessEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_file_event(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: file_access
            product: windows
        detection:
            sel:
                FileName: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceFileEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_image_load(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceImageLoadEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_registry_event(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceRegistryEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_unsupported_field_network_connection(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                CommandLine: whatever
                InvalidField: forever
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*DeviceNetworkEvents"
    ):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_no_valid_hashes(xdr_backend):
    yaml_rule = """
        title: test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                Hashes: 
                    - IMPHASH=6444f8a34e99b8f7d9647de66aabe516
                    - IMPHASH=dfd6aa3f7b2b1035b76b718f1ddc689f
                    - IMPHASH=1a6cca4d5460b1710a12dea39e4a592c
            condition: sel
    """
    with pytest.raises(InvalidHashAlgorithmError):
        xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_microsoft_xdr_pipeline_custom_table(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: actuallyafileevent.exe
            condition: sel
    """
    expected_result = ["DeviceFileEvents\n| " 'where InitiatingProcessFolderPath =~ "actuallyafileevent.exe"']

    assert (
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(query_table="DeviceFileEvents")).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )
        == expected_result
    )


def test_microsoft_xdr_pipeline_custom_table_invalid_category(xdr_backend):
    yaml_rule = """
        title: Test
        status: test
        logsource:
            product: windows
        detection:
            sel:
                Image: actuallyafileevent.exe
            condition: sel
    """
    expected_result = ["DeviceFileEvents\n| " 'where InitiatingProcessFolderPath =~ "actuallyafileevent.exe"']

    assert (
        KustoBackend(processing_pipeline=microsoft_xdr_pipeline(query_table="DeviceFileEvents")).convert(
            SigmaCollection.from_yaml(yaml_rule)
        )
        == expected_result
    )


def test_microsoft_xdr_pipeline_SigmaNumbers(xdr_backend):
    yaml_rule = r"""
title: Azure AD Health Monitoring Agent Registry Keys Access
id: ff151c33-45fa-475d-af4f-c2f93571f4fe
status: test
description: |
    This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent.
    This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent.
references:
    - https://o365blog.com/post/hybridhealthagent/
    - https://github.com/OTRF/Set-AuditRule/blob/c3dec5443414231714d850565d364ca73475ade5/rules/registry/aad_connect_health_monitoring_agent.yml
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
date: 2021-08-26
modified: 2022-10-09
tags:
    - attack.discovery
    - attack.t1012
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4656
            - 4663
        ObjectType: 'Key'
        ObjectName: '\REGISTRY\MACHINE\SOFTWARE\Microsoft\Microsoft Online\Reporting\MonitoringAgent'
    filter:
        ProcessName|contains:
            - 'Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe'
            - 'Microsoft.Identity.Health.Adfs.InsightsService.exe'
            - 'Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe'
            - 'Microsoft.Identity.Health.Adfs.PshSurrogate.exe'
            - 'Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
"""

    expected_result = [
        r"""DeviceRegistryEvents
| where RegistryKey =~ "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Microsoft Online\\Reporting\\MonitoringAgent" and (not((InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.InsightsService.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe")))"""
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_eventid_mapping(xdr_backend):
    """Test that EventID is used to determine table when category is missing"""
    yaml_rule = """
        title: Test EventID Mapping
        status: test
        logsource:
            product: windows
        detection:
            sel:
                EventID: 1
                Image: C:\\Windows\\System32\\cmd.exe
            condition: sel
    """
    # EventID 1 should map to process_creation category -> DeviceProcessEvents table
    expected_result = ['DeviceProcessEvents\n| where FolderPath =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"']

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_microsoft_xdr_category_precedence(xdr_backend):
    """Test that category takes precedence over EventID when both are present"""
    yaml_rule = """
        title: Test Category Precedence
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                EventID: 1  # Process creation EventID, but should use file_event category
                Image: C:\\Windows\\System32\\cmd.exe
            condition: sel
    """
    # Should use DeviceFileEvents table based on category, not DeviceProcessEvents from EventID
    expected_result = [
        'DeviceFileEvents\n| where InitiatingProcessFolderPath =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
    ]

    assert xdr_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert xdr_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


# pySigma 1.0.0 Compatibility Edge Case Tests - Microsoft XDR
# These tests validate transformation compatibility with Breaking Change #2 (SigmaDetectionItem initialization)


def test_microsoft_xdr_field_validation_with_hashes_field():
    """
    Test that the special-cased 'Hashes' field is allowed.
    Edge case: Hashes is added to valid_fields in _get_valid_fields().
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Test Hashes Field
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Hashes: 'MD5=123'
            condition: sel
    """

    # Should not raise error - Hashes is a valid field
    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1


def test_microsoft_xdr_username_transformation_with_domain():
    """
    Test Microsoft XDR username transformation with domain\\username format.
    Edge case: Ensure transformation creates proper SigmaDetectionItem with SigmaString values.
    This tests Breaking Change #2 compliance (no auto-conversion of plain types).
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Username with Domain
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                User: DOMAIN\\username
            condition: sel
    """

    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    # Should have both AccountName and AccountDomain conditions
    assert "AccountName" in result[0]
    assert "AccountDomain" in result[0]


def test_microsoft_xdr_field_mapping_transformation_order():
    """
    Test that field mappings are applied before field validation.
    Edge case: A field that's invalid in the schema but has a mapping should be allowed.
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Test Field Mapping
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: C:\\Windows\\System32\\cmd.exe
                CommandLine: whoami
            condition: sel
    """

    # Image should be mapped to a valid XDR field
    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1


def test_microsoft_xdr_registry_key_replacement_transformation():
    """
    Test that registry key replacements work correctly.
    Edge case: Ensure string replacements don't break with pySigma 1.0.0.
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Registry Key Replacement
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                TargetObject: HKLM\\Software\\Test
            condition: sel
    """

    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    # HKLM should be replaced with HKEY_LOCAL_MACHINE
    assert "HKEY_LOCAL_MACHINE" in result[0]
    assert "HKLM" not in result[0] or "HKEY_LOCAL_MACHINE\\\\Software" in result[0]


def test_microsoft_xdr_hashes_field_transformation():
    """
    Test that Hashes field transformation works correctly.
    Edge case: Ensure hash extraction and field mapping works with pySigma 1.0.0.
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Test Hashes Transformation
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Hashes:
                    - MD5=1234567890abcdef
                    - SHA256=abcdef1234567890
            condition: sel
    """

    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    # Should have hash fields
    assert "MD5" in result[0] or "SHA256" in result[0]


def test_microsoft_xdr_username_without_domain_separator():
    """
    Test username transformation when username has no domain separator.
    Edge case for SplitDomainUserTransformation line 47-58.
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rule_yaml = """
        title: Username Without Domain
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                User: administrator
            condition: sel
    """

    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    assert "DeviceProcessEvents" in result[0]
    # Should handle username without domain separator
    assert "AccountName" in result[0] or "InitiatingProcessAccountName" in result[0]
    assert "administrator" in result[0]


def test_microsoft_xdr_postprocessing_factory_pattern():
    """
    Test that postprocessing items are created fresh for each pipeline.
    v1.0 Breaking Change #12: Ensures factory pattern for postprocessing items.
    """
    from sigma.pipelines.kusto_common.postprocessing import create_prepend_query_table_item

    item1 = create_prepend_query_table_item()
    item2 = create_prepend_query_table_item()

    # Should be different instances
    assert item1 is not item2
    assert item1.transformation is not item2.transformation


# ─── Correlation rule tests ───────────────────────────────────────────────────


def test_microsoft_xdr_correlation_single_rule_value_count():
    """Single-rule value_count correlation: table is prepended by postprocessing."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami
    condition: sel
---
title: Multiple Suspicious Processes
status: test
correlation:
    type: value_count
    rules:
        - susp_process
    group-by:
        - AccountName
    timespan: 5m
    condition:
        gte: 10
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    # Only the correlation query is returned (base rule is consumed)
    assert len(result) == 1
    query = result[0]
    assert "DeviceProcessEvents" in query
    assert 'ProcessCommandLine =~ "whoami"' in query
    assert "summarize ValueCount = count_distinct(AccountName)" in query
    assert "bin(Timestamp, 5m)" in query
    assert "| where ValueCount >= 10" in query


def test_microsoft_xdr_correlation_single_rule_value_avg():
    """Single-rule value_avg correlation."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: mimikatz
    condition: sel
---
title: High Avg
status: test
correlation:
    type: value_avg
    rules:
        - susp_process
    group-by:
        - AccountName
    timespan: 10m
    condition:
        gte: 5
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceProcessEvents" in query
    assert "summarize ValueAvg = avg(AccountName)" in query
    assert "bin(Timestamp, 10m)" in query
    assert "| where ValueAvg >= 5" in query


def test_microsoft_xdr_correlation_single_rule_event_count():
    """Single-rule event_count correlation."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: mimikatz
    condition: sel
---
title: High Event Count
status: test
correlation:
    type: event_count
    rules:
        - susp_process
    group-by:
        - AccountName
    timespan: 10m
    condition:
        gte: 5
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceProcessEvents" in query
    assert "summarize EventCount = count()" in query
    assert "bin(Timestamp, 10m)" in query
    assert "| where EventCount >= 5" in query


def test_microsoft_xdr_correlation_event_count_different_table():
    """event_count correlation where base rule targets DeviceNetworkEvents."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Connection
name: susp_conn
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 4444
    condition: sel
---
title: Many Connections
status: test
correlation:
    type: event_count
    rules:
        - susp_conn
    group-by:
        - AccountName
    timespan: 5m
    condition:
        gte: 10
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceNetworkEvents" in query
    assert "summarize EventCount = count()" in query
    assert "bin(Timestamp, 5m)" in query
    assert "| where EventCount >= 10" in query


def test_microsoft_xdr_correlation_event_count_lte_operator():
    """event_count correlation using a lte threshold operator."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: mimikatz
    condition: sel
---
title: Low Event Count
status: test
correlation:
    type: event_count
    rules:
        - susp_process
    group-by:
        - AccountName
    timespan: 10m
    condition:
        lte: 3
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceProcessEvents" in query
    assert "summarize EventCount = count()" in query
    assert "| where EventCount <= 3" in query


def test_microsoft_xdr_correlation_multi_rule_event_count():
    """Multi-rule event_count correlation: sub-queries are unioned."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami
    condition: sel
---
title: Suspicious File
name: susp_file
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename|endswith: .exe
    condition: sel
---
title: Combined Event Count
status: test
correlation:
    type: event_count
    rules:
        - susp_process
        - susp_file
    group-by:
        - AccountName
    timespan: 5m
    condition:
        gte: 10
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert query.startswith("union")
    assert "DeviceProcessEvents" in query
    assert "DeviceFileEvents" in query
    assert "summarize EventCount = count()" in query
    assert "bin(Timestamp, 5m)" in query
    assert "| where EventCount >= 10" in query


def test_microsoft_xdr_correlation_single_rule_table_from_network_connection():
    """Single-rule correlation where base rule targets DeviceNetworkEvents."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Connection
name: susp_conn
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 4444
    condition: sel
---
title: Many Connections
status: test
correlation:
    type: value_count
    rules:
        - susp_conn
    group-by:
        - AccountName
    timespan: 5m
    condition:
        gte: 5
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceNetworkEvents" in query
    assert "summarize ValueCount" in query


def test_microsoft_xdr_correlation_multi_rule_value_count():
    """Multi-rule value_count correlation: each sub-query gets its own table prefix,
    and the result is a union without a top-level table prefix."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami
    condition: sel
---
title: Suspicious File
name: susp_file
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename|endswith: .exe
    condition: sel
---
title: Combined Suspicious Activity
status: test
correlation:
    type: value_count
    rules:
        - susp_process
        - susp_file
    group-by:
        - AccountName
    timespan: 5m
    condition:
        gte: 10
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert query.startswith("union")
    assert "DeviceProcessEvents" in query
    assert "DeviceFileEvents" in query
    assert 'ProcessCommandLine =~ "whoami"' in query
    assert 'FolderPath endswith ".exe"' in query
    assert "summarize ValueCount = count_distinct(AccountName)" in query
    assert "bin(Timestamp, 5m)" in query
    assert "| where ValueCount >= 10" in query


def test_microsoft_xdr_correlation_multi_rule_three_tables():
    """Multi-rule correlation spanning three different tables."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Process
name: susp_process
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami
    condition: sel
---
title: Suspicious File
name: susp_file
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename|endswith: .ps1
    condition: sel
---
title: Suspicious Connection
name: susp_conn
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 4444
    condition: sel
---
title: Multi-table Correlation
status: test
correlation:
    type: value_count
    rules:
        - susp_process
        - susp_file
        - susp_conn
    group-by:
        - AccountName
    timespan: 15m
    condition:
        gte: 3
        field: AccountName
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert query.startswith("union")
    assert "DeviceProcessEvents" in query
    assert "DeviceFileEvents" in query
    assert "DeviceNetworkEvents" in query
    assert "summarize ValueCount" in query
    assert "| where ValueCount >= 3" in query


def test_microsoft_xdr_pipeline_reuse_state_reset():
    """
    Test that pipeline state resets correctly across multiple rule conversions.
    v1.0 Breaking Change #11: Pipeline initialized once, state resets per apply().
    """
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())

    rules_yaml = """
---
title: Process Rule 1
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami.exe
    condition: sel
---
title: Registry Rule
status: test
logsource:
    category: registry_event
    product: windows
detection:
    sel:
        TargetObject: "HKLM\\\\Software\\\\Test"
    condition: sel
---
title: File Event Rule
status: test
logsource:
    category: file_event
    product: windows
detection:
    sel:
        TargetFilename: "test.exe"
    condition: sel
---
title: Process Rule 2
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: cmd.exe
    condition: sel
    """

    collection = SigmaCollection.from_yaml(rules_yaml)
    results = backend.convert(collection)

    # Verify correct tables are used and state resets properly between rules
    assert len(results) == 4
    assert "DeviceProcessEvents" in results[0]
    assert "whoami.exe" in results[0]
    assert "DeviceRegistryEvents" in results[1]
    assert "RegistryKey" in results[1]
    assert "DeviceFileEvents" in results[2]
    assert "FolderPath" in results[2]  # Field is mapped to FolderPath
    assert "test.exe" in results[2]
    assert "DeviceProcessEvents" in results[3]
    assert "cmd.exe" in results[3]


def test_microsoft_xdr_correlation_multi_rule_temporal():
    """Multi-rule temporal correlation: each sub-query is tagged with its rule ID and
    TemporalCount uses count_distinct(EventType) to detect distinct event types co-occurring."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Suspicious Connection
name: susp_conn
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 4444
    condition: sel
---
title: Suspicious Process
name: susp_proc
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: powershell.exe
    condition: sel
---
title: Exploit Chain
status: test
correlation:
    type: temporal
    rules:
        - susp_conn
        - susp_proc
    group-by:
        - AccountName
    timespan: 10s
    condition:
        gte: 2
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert query.startswith("union")
    assert "DeviceNetworkEvents" in query
    assert "DeviceProcessEvents" in query
    # Each sub-query must be tagged with its rule name
    assert '| extend EventType = "susp_conn"' in query
    assert '| extend EventType = "susp_proc"' in query
    # Aggregation must count distinct event types, not total events
    assert "summarize TemporalCount = count_distinct(EventType)" in query
    assert "bin(Timestamp, 10s)" in query
    assert ", AccountName" in query
    assert "| where TemporalCount >= 2" in query


def test_microsoft_xdr_correlation_temporal_without_groupby():
    """Temporal correlation with no group-by clause."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Brute Force
name: brute_force
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: failed
    condition: sel
---
title: Successful Logon
name: succ_logon
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: success
    condition: sel
---
title: Brute Force Success
status: test
correlation:
    type: temporal
    rules:
        - brute_force
        - succ_logon
    timespan: 5m
    condition:
        gte: 2
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "summarize TemporalCount = count_distinct(EventType) by bin(Timestamp, 5m)" in query
    assert "| where TemporalCount >= 2" in query
    # No trailing group-by fields
    assert "AccountName" not in query


def test_microsoft_xdr_correlation_temporal_ordered():
    """Multi-rule temporal_ordered correlation: events must appear in declared order within the window."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Failed Logon
name: failed_logon
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: failed_logon
    condition: sel
---
title: Successful Logon
name: succ_logon
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine|contains: successful_logon
    condition: sel
---
title: Suspicious Process
name: susp_proc
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: cmd.exe
    condition: sel
---
title: Brute Force Then Execute
status: test
correlation:
    type: temporal_ordered
    rules:
        - failed_logon
        - succ_logon
        - susp_proc
    group-by:
        - AccountName
    timespan: 10m
    condition:
        gte: 3
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert query.startswith("union")
    # Each sub-query tagged with both EventType and EventOrder
    assert '| extend EventType = "failed_logon", EventOrder = 1' in query
    assert '| extend EventType = "succ_logon", EventOrder = 2' in query
    assert '| extend EventType = "susp_proc", EventOrder = 3' in query
    # Aggregation captures first occurrence per event type
    assert "summarize TemporalCount = count_distinct(EventType)" in query
    assert "FirstTs1 = minif(Timestamp, EventOrder == 1)" in query
    assert "FirstTs2 = minif(Timestamp, EventOrder == 2)" in query
    assert "FirstTs3 = minif(Timestamp, EventOrder == 3)" in query
    assert "bin(Timestamp, 10m)" in query
    assert ", AccountName" in query
    # Ordering constraints must be present
    assert "| where TemporalCount >= 3 and FirstTs1 < FirstTs2 and FirstTs2 < FirstTs3" in query


def test_microsoft_xdr_correlation_temporal_ordered_two_rules():
    """temporal_ordered with exactly two rules: one ordering constraint."""
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    yaml_rules = """
title: Network Recon
name: net_recon
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 445
    condition: sel
---
title: Lateral Move
name: lateral_move
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        Image|endswith: psexec.exe
    condition: sel
---
title: Recon Then Lateral Movement
status: test
correlation:
    type: temporal_ordered
    rules:
        - net_recon
        - lateral_move
    timespan: 5m
    condition:
        gte: 2
"""
    result = backend.convert(SigmaCollection.from_yaml(yaml_rules))
    assert len(result) == 1
    query = result[0]
    assert "DeviceNetworkEvents" in query
    assert "DeviceProcessEvents" in query
    assert '| extend EventType = "net_recon", EventOrder = 1' in query
    assert '| extend EventType = "lateral_move", EventOrder = 2' in query
    assert "FirstTs1 = minif(Timestamp, EventOrder == 1)" in query
    assert "FirstTs2 = minif(Timestamp, EventOrder == 2)" in query
    # Single ordering constraint with no group-by
    assert "| where TemporalCount >= 2 and FirstTs1 < FirstTs2" in query
    assert "FirstTs2 < FirstTs3" not in query
