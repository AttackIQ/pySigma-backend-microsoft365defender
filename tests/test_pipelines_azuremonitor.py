import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.rule import SigmaRule


@pytest.fixture
def azure_backend():
    return KustoBackend(processing_pipeline=azure_monitor_pipeline())


def test_azure_monitor_process_creation_field_mapping(azure_backend):
    yaml_rule = """
        title: Test Process Creation
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Image: C:\\Windows\\System32\\cmd.exe
                CommandLine: whoami
                User: SYSTEM
                ProcessId: 1234
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe" and CommandLine =~ "whoami" and SubjectUserName =~ "SYSTEM" and NewProcessId == 1234'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_network_connection_field_mapping(azure_backend):
    yaml_rule = """
        title: Test Network Connection
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                DestinationIp: 8.8.8.8
                DestinationPort: 53
                SourcePort: 12345
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where DestinationIp =~ "8.8.8.8" and DestinationPort == 53 and SourcePort == 12345'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_registry_event_field_mapping(azure_backend):
    yaml_rule = """
        title: Test Registry Event
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                EventID: 13
                TargetObject: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where EventID == 13 and ObjectName =~ "HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_file_event_field_mapping(azure_backend):
    yaml_rule = """
        title: Test File Event
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                TargetFilename: C:\\suspicious\\file.exe
                Image: C:\\Windows\\System32\\cmd.exe
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where ObjectName =~ "C:\\\\suspicious\\\\file.exe" and NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_hashes_transformation(azure_backend):
    yaml_rule = """
        title: Test Hashes
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                Hashes:
                    - md5=1234567890abcdef1234567890abcdef
                    - sha1=1234567890abcdef1234567890abcdef12345678
                    - sha256=1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where FileHash in~ ("1234567890abcdef1234567890abcdef", "1234567890abcdef1234567890abcdef12345678", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_registry_key_replacement(azure_backend):
    yaml_rule = """
        title: Test Registry Key Replacement
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                TargetObject:
                    - HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                    - HKU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
                    - HKCR\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
            condition: sel
    """
    expected_result = [
        'SecurityEvent\n| where ObjectName in~ ("HKEY_LOCAL_MACHINE\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKEY_USERS\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", "HKEY_LOCAL_MACHINE\\\\CLASSES\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_unsupported_category(azure_backend):
    yaml_rule = """
        title: Test Unsupported Category
        status: test
        logsource:
            category: unsupported_category
            product: windows
        detection:
            sel:
                Field: value
            condition: sel
    """
    with pytest.raises(SigmaTransformationError, match="Unable to determine table name from rule. "):
        azure_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_azure_monitor_invalid_field(azure_backend):
    yaml_rule = """
        title: Test Invalid Field
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                InvalidField: value
            condition: sel
    """
    with pytest.raises(
        SigmaTransformationError, match="Invalid SigmaDetectionItem field name encountered.*SecurityEvent"
    ):
        azure_backend.convert(SigmaCollection.from_yaml(yaml_rule))


def test_azure_monitor_custom_query_table():
    yaml_rule = """
        title: Test Custom Query Table
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """
    expected_result = ['CustomTable\n| where CommandLine =~ "whoami"']

    custom_backend = KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table="CustomTable"))
    assert custom_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert custom_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_pipeline_custom_table_invalid_category():
    yaml_rule = """
        title: Test
        status: test
        logsource:
            product: windows
            category: blah
        detection:
            sel:
                Image: actuallyafileevent.exe
            condition: sel
    """
    expected_result = ["SecurityEvent\n| " 'where NewProcessName =~ "actuallyafileevent.exe"']

    custom_backend = KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table="SecurityEvent"))
    assert custom_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert custom_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_eventid_mapping(azure_backend):
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
    # All EventIDs should map to SecurityEvent table
    expected_result = [
        'SecurityEvent\n| where EventID == 1 and NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


def test_azure_monitor_category_precedence(azure_backend):
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
    # Should use SecurityEvent table based on category mapping
    expected_result = [
        'SecurityEvent\n| where EventID == 1 and NewProcessName =~ "C:\\\\Windows\\\\System32\\\\cmd.exe"'
    ]

    assert azure_backend.convert(SigmaCollection.from_yaml(yaml_rule)) == expected_result
    assert azure_backend.convert_rule(SigmaRule.from_yaml(yaml_rule)) == expected_result


# pySigma 1.0.0 Compatibility Edge Case Tests
# These tests validate Breaking Changes #11 (Pipeline Initialization) and #12 (ProcessingItem Reference Assignment)


def test_azure_monitor_multiple_rules_same_backend(azure_backend):
    """
    Test that the same backend instance can convert multiple rules.
    Breaking Change #11: Pipeline initialized once per backend, state resets per apply().
    """
    rule1 = """
        title: Rule 1
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    rule2 = """
        title: Rule 2
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                DestinationPort: 443
            condition: sel
    """

    # Convert first rule
    result1 = azure_backend.convert(SigmaCollection.from_yaml(rule1))
    assert len(result1) == 1
    assert "SecurityEvent" in result1[0]
    assert "CommandLine" in result1[0]

    # Convert second rule with same backend - should work and use different table
    result2 = azure_backend.convert(SigmaCollection.from_yaml(rule2))
    assert len(result2) == 1
    assert "SecurityEvent" in result2[0]
    assert "DestinationPort" in result2[0]


def test_azure_monitor_processing_item_applied_tracking(azure_backend):
    """
    Test that processing items are correctly tracked as applied.
    This validates the fix for SetQueryTableStateTransformation to mark itself as applied.
    """
    rule_yaml = """
        title: Test Applied Tracking
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                InvalidField: value
            condition: sel
    """

    # Should raise error because InvalidField is not valid
    with pytest.raises(SigmaTransformationError, match="Invalid SigmaDetectionItem field name"):
        azure_backend.convert(SigmaCollection.from_yaml(rule_yaml))


def test_azure_monitor_field_validation_with_generic_mappings(azure_backend):
    """
    Test that field validation works correctly with fields from generic_mappings.
    Edge case: fields that are valid via generic mappings should not raise errors.
    """
    # CommandLine is in generic_mappings for Azure Monitor
    rule_yaml = """
        title: Test Generic Mapping
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    result = azure_backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    assert "CommandLine" in result[0]


def test_azure_monitor_multiple_rules_in_collection(azure_backend):
    """
    Test converting a collection with multiple rules.
    Edge case: Ensure state management works correctly across rules in a collection.
    """
    yaml_rules = """
---
title: Rule 1
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami
    condition: sel
---
title: Rule 2
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 443
    condition: sel
    """

    collection = SigmaCollection.from_yaml(yaml_rules)
    assert len(collection.rules) == 2

    results = azure_backend.convert(collection)
    assert len(results) == 2
    assert "CommandLine" in results[0]
    assert "DestinationPort" in results[1]


def test_azure_monitor_query_table_state_priority():
    """
    Test the priority order for query_table determination.
    Priority: 1) val parameter, 2) existing state, 3) category mapping, 4) EventID
    """
    # Test priority 1: val parameter overrides everything
    backend = KustoBackend(processing_pipeline=azure_monitor_pipeline(query_table="CustomTable"))

    rule_yaml = """
        title: Test Priority
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    result = backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert "CustomTable" in result[0]
    assert "SecurityEvent" not in result[0]


def test_azure_monitor_invalid_field_after_valid_conversion(azure_backend):
    """
    Test that field validation works correctly even after successful conversions.
    Edge case: Ensure the processing item applied tracking doesn't break across multiple conversions.
    """
    valid_rule = """
        title: Valid Rule
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    invalid_rule = """
        title: Invalid Rule
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                InvalidField: value
            condition: sel
    """

    # First conversion should succeed
    result = azure_backend.convert(SigmaCollection.from_yaml(valid_rule))
    assert len(result) == 1

    # Second conversion should fail due to invalid field
    with pytest.raises(SigmaTransformationError, match="Invalid SigmaDetectionItem field name"):
        azure_backend.convert(SigmaCollection.from_yaml(invalid_rule))


def test_azure_monitor_nested_detections_field_validation(azure_backend):
    """
    Test field validation with nested detection items.
    Edge case: Ensure field validation works in nested detections (detection within detection).
    """
    rule_yaml = """
        title: Nested Detection Invalid Field
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel1:
                CommandLine: whoami
            sel2:
                InvalidField: value
            condition: sel1 or sel2
    """

    # Should raise error for InvalidField even in nested detection
    with pytest.raises(SigmaTransformationError, match="Invalid SigmaDetectionItem field name"):
        azure_backend.convert(SigmaCollection.from_yaml(rule_yaml))


def test_azure_monitor_different_logsource_categories_same_backend(azure_backend):
    """
    Test that state properly resets between rules with different logsource categories.
    Edge case: Ensure query_table state changes correctly for different categories.
    """
    process_rule = """
        title: Process Rule
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    network_rule = """
        title: Network Rule
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
                DestinationPort: 443
            condition: sel
    """

    # Both should use SecurityEvent table
    result1 = azure_backend.convert(SigmaCollection.from_yaml(process_rule))
    assert "SecurityEvent" in result1[0]

    result2 = azure_backend.convert(SigmaCollection.from_yaml(network_rule))
    assert "SecurityEvent" in result2[0]


def test_azure_monitor_eventid_based_table_mapping(azure_backend):
    """
    Test that EventID-based table mapping works correctly.
    Edge case: Query table determination priority #4 (EventID mapping).
    """
    rule_yaml = """
        title: EventID Based Mapping
        status: test
        logsource:
            product: windows
        detection:
            sel:
                EventID: 4688
            condition: sel
    """

    # EventID 4688 is process creation, should map to SecurityEvent
    result = azure_backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    assert "SecurityEvent" in result[0]


def test_azure_monitor_correlation_rule_compatibility(azure_backend):
    """
    Test that correlation rules include table and where prefix with pipeline-managed query table.
    """
    rule_yaml = """
title: High-privilege group enumeration
name: privileged_group_enumeration
status: stable
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: whoami
        User: SYSTEM
    condition: selection
---
title: Enumeration of multiple high-privilege groups by tools like BloodHound
status: stable
correlation:
    type: value_count
    rules:
        - privileged_group_enumeration
    group-by:
        - SubjectUserName
    timespan: 15m
    condition:
        gte: 1
        field: CommandLine
"""

    result = azure_backend.convert(SigmaCollection.from_yaml(rule_yaml))
    assert len(result) == 1
    assert result[0].startswith("SecurityEvent\n| where ")


def test_azure_monitor_pipeline_state_isolation():
    """
    Test that pipeline state is properly isolated between different backend instances.
    Edge case: Ensure Breaking Change #11 (pipeline initialized once per backend) works correctly.
    """
    backend1 = KustoBackend(processing_pipeline=azure_monitor_pipeline())
    backend2 = KustoBackend(processing_pipeline=azure_monitor_pipeline())

    rule_yaml = """
        title: Test State Isolation
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: whoami
            condition: sel
    """

    result1 = backend1.convert(SigmaCollection.from_yaml(rule_yaml))
    result2 = backend2.convert(SigmaCollection.from_yaml(rule_yaml))

    # Both should produce the same result
    assert result1 == result2


def test_azure_monitor_pipeline_reuse_multiple_backends():
    """
    Test that a single pipeline can be used to create multiple backend instances.
    v1.0 Breaking Change #12: Ensures factory pattern works correctly.
    """
    pipeline = azure_monitor_pipeline()

    # Create two backends with the same pipeline instance
    backend1 = KustoBackend(processing_pipeline=pipeline)
    backend2 = KustoBackend(processing_pipeline=pipeline)

    rule = SigmaRule.from_yaml(
        """
        title: Test Pipeline Reuse
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: test.exe
            condition: sel
    """
    )

    # Both should work independently without state conflicts
    result1 = backend1.convert_rule(rule)
    result2 = backend2.convert_rule(rule)

    assert result1 == result2
    assert len(result1) == 1
    assert "SecurityEvent" in result1[0]
    assert "test.exe" in result1[0]


def test_azure_monitor_no_category_no_eventid():
    """
    Test error when rule has no category and no EventID.
    Ensures proper error handling with source tracking (v1.0).
    """
    backend = KustoBackend(processing_pipeline=azure_monitor_pipeline())

    rule_yaml = """
        title: No Category or EventID
        status: test
        logsource:
            product: windows
        detection:
            sel:
                CommandLine: test
            condition: sel
    """

    with pytest.raises(SigmaTransformationError, match="Unable to determine table name"):
        backend.convert(SigmaCollection.from_yaml(rule_yaml))


def test_azure_monitor_state_reset_multiple_categories():
    """
    Test that pipeline state resets correctly between rules with different categories.
    v1.0 Breaking Change #11: Ensures state management works across rule conversions.
    """
    backend = KustoBackend(processing_pipeline=azure_monitor_pipeline())

    rules_yaml = """
---
title: Process Rule
status: test
logsource:
    category: process_creation
    product: windows
detection:
    sel:
        CommandLine: whoami.exe
    condition: sel
---
title: Network Rule
status: test
logsource:
    category: network_connection
    product: windows
detection:
    sel:
        DestinationPort: 443
    condition: sel
---
title: Another Process Rule
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

    # Verify correct tables are used and state resets properly
    assert len(results) == 3
    assert "SecurityEvent" in results[0]
    assert "whoami.exe" in results[0]
    assert "SecurityEvent" in results[1]
    assert "DestinationPort" in results[1]
    assert "SecurityEvent" in results[2]
    assert "cmd.exe" in results[2]
