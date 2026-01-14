from typing import Iterable, Optional, Union

from sigma.processing.transformations.base import DetectionItemTransformation, ValueTransformation
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString, SigmaType, SigmaNumber

from ..kusto_common.transformations import BaseHashesValuesTransformation


## Custom DetectionItemTransformation to split domain and user, if applicable
class SplitDomainUserTransformation(DetectionItemTransformation):
    """Custom DetectionItemTransformation transformation to split a User field into separate domain and user fields,
    if applicable.  This is to handle the case where the Sysmon `User` field may contain a domain AND username, and
    Advanced Hunting queries separate out the domain and username into separate fields.
    If a matching field_name_condition field uses the schema DOMAIN\\USER, a new SigmaDetectionItem
    will be made for the Domain and put inside a SigmaDetection with the original User SigmaDetectionItem
    (minus the domain) for the matching SigmaDetectionItem.

    You should use this with a field_name_condition for `IncludeFieldName(['field', 'names', 'for', 'username']`)"""

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        to_return = []
        if not isinstance(detection_item.value, list):  # Ensure its a list, but it most likely will be
            detection_item.value = list(detection_item.value)
        for d in detection_item.value:
            username = d.to_plain().split("\\")
            username_field_mappings = {
                "AccountName": "AccountDomain",
                "RequestAccountName": "RequestAccountDomain",
                "InitiatingProcessAccountName": "InitiatingProcessAccountDomain",
            }
            if len(username) == 2:
                domain = username[0]
                username = [SigmaString(username[1])]

                domain_field = username_field_mappings.get(detection_item.field, "InitiatingProcessAccountDomain")
                domain_value = [SigmaString(domain)]
                user_detection_item = SigmaDetectionItem(
                    field=detection_item.field,
                    modifiers=[],
                    value=username,
                )
                domain_detection_item = SigmaDetectionItem(field=domain_field, modifiers=[], value=domain_value)
                to_return.append(SigmaDetection(detection_items=[user_detection_item, domain_detection_item]))
            else:
                to_return.append(
                    SigmaDetection(
                        [
                            SigmaDetectionItem(
                                field=detection_item.field,
                                modifiers=detection_item.modifiers,
                                value=[SigmaString(u) for u in username],
                            )
                        ]
                    )
                )
        return SigmaDetection(to_return)


# Extract parent process name from ParentImage after applying ParentImage field mapping
class ParentImageValueTransformation(ValueTransformation):
    """Custom ValueTransformation transformation.  Unfortunately, none of the table schemas have
    InitiatingProcessParentFolderPath like they do InitiatingProcessFolderPath. Due to this, we cannot directly map the
    Sysmon `ParentImage` field to a table field. However, InitiatingProcessParentFileName is an available field in
    nearly all tables, so we will extract the process name and use that instead.

    Use this transformation BEFORE mapping ParentImage to InitiatingProcessFileName
    """

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        parent_process_name = str(val.to_plain().split("\\")[-1].split("/")[-1])
        return SigmaString(parent_process_name)


class XDRHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in XDR Tables to create fields for each hash algorithm.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256"], field_prefix="")


class LogonIdValueTransformation(ValueTransformation):
    """
    Custom ValueTransformation for LogonId fields to ensure exact string matching.
    LogonId values like "0x3e7" should use exact equality (==) not case-insensitive (=~).
    This transformation adds a modifier to mark the value for exact matching.
    """

    def apply_value(self, field: str, val: SigmaType) -> Optional[Union[SigmaType, Iterable[SigmaType]]]:
        # Return the value as a SigmaNumber if it's a numeric string or hex value
        # This forces the backend to use == instead of =~
        value_str = val.to_plain()
        
        # Convert hex strings to decimal for numeric comparison
        if isinstance(value_str, str) and value_str.lower().startswith("0x"):
            try:
                # Convert hex to decimal integer
                numeric_value = int(value_str, 16)
                return SigmaNumber(numeric_value)
            except ValueError:
                # If conversion fails, return as-is
                pass
        
        return val
