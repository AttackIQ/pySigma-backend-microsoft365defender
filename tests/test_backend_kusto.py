import pytest

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.microsoft365defender import microsoft_365_defender_pipeline


@pytest.fixture
def microsoft365defender_backend():
    return KustoBackend(processing_pipeline=microsoft_365_defender_pipeline())


@pytest.fixture
def kusto_backend_no_pipeline():
    return KustoBackend()


def test_kusto_and_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: valueA
                    User: valueB
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" and AccountName =~ "valueB"']
    )


def test_kusto_or_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA
                sel2:
                    User: valueB
                condition: 1 of sel*
        """
            )
        )
        == ['DeviceProcessEvents\n| where ProcessCommandLine =~ "valueA" or AccountName =~ "valueB"']
    )


def test_kusto_and_or_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA1
                        - valueA2
                    ProcessId:
                        - valueB1
                        - valueB2
                condition: sel
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (ProcessCommandLine in~ ("valueA1", "valueA2")) and '
            '(ProcessId in~ ("valueB1", "valueB2"))'
        ]
    )


def test_kusto_or_and_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel1:
                    CommandLine: valueA1
                    ProcessId: valueB1
                sel2:
                    CommandLine: valueA2
                    ProcessId: valueB2
                condition: 1 of sel*
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (ProcessCommandLine =~ "valueA1" and ProcessId =~ "valueB1") or '
            '(ProcessCommandLine =~ "valueA2" and ProcessId =~ "valueB2")'
        ]
    )


def test_kusto_in_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where ProcessCommandLine in~ ("valueA", "valueB") or '
            'ProcessCommandLine startswith "valueC"'
        ]
    )


def test_kusto_regex_query(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|re: 
                        - foo.*bar
                        - -(W|R)\s?(\s|"|')([0-9a-fA-F]{2}\s?){2,20}(\s|"|')
                    ProcessId: foo
                condition: sel
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (ProcessCommandLine matches regex "foo.*bar" or '
            'ProcessCommandLine matches regex "-(W|R)\\\\s?(\\\\s|\\"|\')([0-9a-fA-F]{2}\\\\s?){2,20}(\\\\s|\\"|\')") and '
            'ProcessId =~ "foo"'
        ]
    )


def test_kusto_cidr_query(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                sel:
                    SourceIp|cidr: 192.168.0.0/16
                condition: sel
        """
            )
        )
        == ['DeviceNetworkEvents\n| where ipv4_is_in_range(LocalIP, "192.168.0.0/16")']
    )


def test_kusto_negation_basic(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - 'this'
                filter:
                    CommandLine:
                        - 'notthis'
                condition: selection and not filter
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
            'ProcessCommandLine =~ "this") and '
            '(not(ProcessCommandLine =~ "notthis"))'
        ]
    )


def test_kusto_negation_contains(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Test
            status: test
            logsource:
                product: windows
                category: process_creation
            detection:
                selection:
                    Image:
                        - '*\process.exe'
                    CommandLine:
                        - '*this*'
                filter:
                    CommandLine:
                        - '*notthis*'
                condition: selection and not filter
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where (FolderPath endswith "\\\\process.exe" and '
            'ProcessCommandLine contains "this") and '
            '(not(ProcessCommandLine contains "notthis"))'
        ]
    )


def test_kusto_grouping(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Net connection logic test
            status: test
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    Image:
                        - '*\powershell.exe'
                        - '*\pwsh.exe'
                    DestinationHostname: 
                        - '*pastebin.com*'
                        - '*anothersite.com*'
                condition: selection
    """
            )
        )
        == [
            'DeviceNetworkEvents\n| where (InitiatingProcessFolderPath endswith "\\\\powershell.exe" or '
            'InitiatingProcessFolderPath endswith "\\\\pwsh.exe") and (RemoteUrl contains '
            '"pastebin.com" or RemoteUrl contains "anothersite.com")'
        ]
    )


def test_kusto_escape_cmdline_slash(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Delete All Scheduled Tasks
            id: 220457c1-1c9f-4c2e-afe6-9598926222c1
            status: test
            description: Detects the usage of schtasks with the delete flag and the asterisk symbol to delete all tasks from the schedule of the local computer, including tasks scheduled by other users.
            references:
                - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete
            author: Nasreddine Bencherchali (Nextron Systems)
            date: 2022-09-09
            tags:
                - attack.impact
                - attack.t1489
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\schtasks.exe'
                    CommandLine|contains|all:
                        - ' /delete '
                        - '/tn \*'
                        - ' /f'
                condition: selection
            falsepositives:
                - Unlikely
            level: high
        """
            )
        )
        == [
            'DeviceProcessEvents\n| where FolderPath endswith "\\\\schtasks.exe" and '
            '(ProcessCommandLine contains " /delete " and '
            'ProcessCommandLine contains "/tn *" and '
            'ProcessCommandLine contains " /f")'
        ]
    )


def test_kusto_cmdline_filters(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: New Firewall Rule Added Via Netsh.EXE
            id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
            status: test
            description: Detects the addition of a new rule to the Windows firewall via netsh
            references:
                - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
            author: Markus Neis, Sander Wiebing
            date: 2019-01-29
            modified: 2023-02-10
            tags:
                - attack.defense_evasion
                - attack.t1562.004
                - attack.s0246
            logsource:
                category: process_creation
                product: windows
            detection:
                selection_img:
                    - Image|endswith: '\netsh.exe'
                    - OriginalFileName: 'netsh.exe'
                selection_cli:
                    CommandLine|contains|all:
                        - ' firewall '
                        - ' add '
                filter_optional_dropbox:
                    CommandLine|contains:
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files (x86)\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                        - 'advfirewall firewall add rule name=Dropbox dir=in action=allow "program=?:\Program Files\Dropbox\Client\Dropbox.exe" enable=yes profile=Any'
                condition: all of selection_* and not 1 of filter_optional_*
            falsepositives:
                - Legitimate administration activity
                - Software installations
            level: medium
            """
            )
        )
        == [
            'DeviceProcessEvents\n| where ((FolderPath endswith "\\\\netsh.exe" or '
            'ProcessVersionInfoOriginalFileName =~ "netsh.exe") and '
            '(ProcessCommandLine contains " firewall " and ProcessCommandLine contains " add ")) and '
            '(not(((ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in action=allow '
            '\\"program=" and ProcessCommandLine contains ":\\\\Program Files (x86)\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" '
            'enable=yes profile=Any") or (ProcessCommandLine contains "advfirewall firewall add rule name=Dropbox dir=in '
            'action=allow \\"program=" and ProcessCommandLine contains ":\\\\Program Files\\\\Dropbox\\\\Client\\\\Dropbox.exe\\" '
            'enable=yes profile=Any"))))'
        ]
    )


def test_kusto_sigmanumber_conversion(kusto_backend_no_pipeline: KustoBackend):
    assert (
        kusto_backend_no_pipeline.convert(
            SigmaCollection.from_yaml(
                """
        title: Test
        status: test
        logsource:
            product: windows
        detection:
            sel:
                EventID: 1
            condition: sel
    """
            )
        )
        == ["EventID == 1"]
    )


def test_kusto_sigmanumber_conversion_mixed_types(kusto_backend_no_pipeline: KustoBackend):
    assert (
        kusto_backend_no_pipeline.convert(
            SigmaCollection.from_yaml(
                r"""
title: ETW Logging Disabled In .NET Processes - Sysmon Registry
id: bf4fc428-dcc3-4bbd-99fe-2422aeee2544
related:
    - id: a4c90ea1-2634-4ca0-adbb-35eae169b6fc
      type: similar
status: test
description: Potential adversaries stopping ETW providers recording loaded .NET assemblies.
references:
    - https://twitter.com/_xpn_/status/1268712093928378368
    - https://social.msdn.microsoft.com/Forums/vstudio/en-US/0878832e-39d7-4eaf-8e16-a729c4c40975/what-can-i-use-e13c0d23ccbc4e12931bd9cc2eee27e4-for?forum=clr
    - https://github.com/dotnet/runtime/blob/ee2355c801d892f2894b0f7b14a20e6cc50e0e54/docs/design/coreclr/jit/viewing-jit-dumps.md#setting-configuration-variables
    - https://github.com/dotnet/runtime/blob/f62e93416a1799aecc6b0947adad55a0d9870732/src/coreclr/src/inc/clrconfigvalues.h#L35-L38
    - https://github.com/dotnet/runtime/blob/7abe42dc1123722ed385218268bb9fe04556e3d3/src/coreclr/src/inc/clrconfig.h#L33-L39
    - https://github.com/dotnet/runtime/search?p=1&q=COMPlus_&unscoped_q=COMPlus_
    - https://bunnyinside.com/?term=f71e8cb9c76a
    - http://managed670.rssing.com/chan-5590147/all_p1.html
    - https://github.com/dotnet/runtime/blob/4f9ae42d861fcb4be2fcd5d3d55d5f227d30e723/docs/coding-guidelines/clr-jit-coding-conventions.md#1412-disabling-code
    - https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/
    - https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
date: 2020-06-05
modified: 2023-08-17
tags:
    - attack.defense-evasion
    - attack.t1112
    - attack.t1562
logsource:
    product: windows
    category: registry_set
detection:
    selection_etw_enabled:
        TargetObject|endswith: 'SOFTWARE\Microsoft\.NETFramework\ETWEnabled'
        Details: 'DWORD (0x00000000)'
    selection_complus:
        TargetObject|endswith:
            - '\COMPlus_ETWEnabled'
            - '\COMPlus_ETWFlags'
        Details:
            - 0 # For REG_SZ type
            - 'DWORD (0x00000000)'
    condition: 1 of selection_*
falsepositives:
    - Unknown
level: high
    """
            )
        )
        == [
            '(TargetObject endswith "SOFTWARE\\\\Microsoft\\\\.NETFramework\\\\ETWEnabled" and Details =~ "DWORD (0x00000000)") or ((TargetObject endswith "\\\\COMPlus_ETWEnabled" or '
            'TargetObject endswith "\\\\COMPlus_ETWFlags") and (Details in~ ("0", "DWORD (0x00000000)")))'
        ]
    )


def test_kusto_exists_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Exists
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|exists: true
                condition: sel
        """
            )
        )
        == ["DeviceProcessEvents\n| where isnotempty(ProcessCommandLine)"]
    )


def test_kusto_not_exists_expression(microsoft365defender_backend: KustoBackend):
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Not Exists
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine|exists: false
                condition: sel
        """
            )
        )
        == ["DeviceProcessEvents\n| where isempty(ProcessCommandLine)"]
    )

def test_kusto_wildcard_regex_multi_char(microsoft365defender_backend: KustoBackend):
    """Test multi-char wildcard (*) in middle of string converts to regex."""
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Wildcard Regex
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: 'foo*bar'
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where FolderPath matches regex "foo.*bar"']
    )


def test_kusto_wildcard_regex_single_char(microsoft365defender_backend: KustoBackend):
    """Test single-char wildcard (?) converts to regex dot."""
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Single Char Wildcard
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: 'foo?bar'
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where FolderPath matches regex "foo.bar"']
    )


def test_kusto_wildcard_regex_multiple(microsoft365defender_backend: KustoBackend):
    """Test multiple wildcards in string convert to regex."""
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Multiple Wildcards
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: 'foo*bar*baz'
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where FolderPath matches regex "foo.*bar.*baz"']
    )


def test_kusto_wildcard_regex_mixed(microsoft365defender_backend: KustoBackend):
    """Test mixed wildcards (? and *) convert to regex."""
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                """
            title: Test Mixed Wildcards
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: 'foo?bar*'
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where FolderPath matches regex "foo.bar.*"']
    )


def test_kusto_wildcard_regex_with_backslashes(microsoft365defender_backend: KustoBackend):
    r"""Test wildcards with escaped backslashes convert to regex with proper escaping."""
    assert (
        microsoft365defender_backend.convert(
            SigmaCollection.from_yaml(
                r"""
            title: Test Wildcards With Backslashes
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: 'C:\Windows*\process.exe'
                condition: sel
        """
            )
        )
        == ['DeviceProcessEvents\n| where FolderPath matches regex "C:\\\\\\\\Windows.*\\\\\\\\process\\\\.exe"']
    )
