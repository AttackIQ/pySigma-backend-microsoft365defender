from typing import Iterable, Optional, Union

from sigma.processing.transformations.base import (
    DetectionItemTransformation,
    ValueTransformation,
)
from sigma.conditions import ConditionOR
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString, SigmaType

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


class SplitFilePathTransformation(DetectionItemTransformation):
    """Split file path into FolderPath and FileName for DeviceEvents.
    
    - Full path (e.g., 'C:\\Windows\\System32\\lsass.exe'): splits into FolderPath and FileName
    - Anything else: maps to FileName only (strips leading slashes)
    """

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        detections = []
        values = detection_item.value if isinstance(detection_item.value, list) else [detection_item.value]
        
        # Supported modifiers and their behavior for (FolderPath, FileName)
        # None implies exact match (no modifier)
        # "keep" implies reuse the original modifier
        modifier_behavior = {
            "SigmaEndswithModifier": ("keep", None),
            "SigmaStartswithModifier": ("keep", "keep"),
            "SigmaContainsModifier": ("keep", "keep"),
        }

        for val in values:
            value_str = val.to_plain()
            
            # Determine modifier type
            modifier_type = detection_item.modifiers[0].__name__ if detection_item.modifiers else None
            
            # Check if we should split
            should_split = (
                ("\\" in value_str or "/" in value_str) and 
                (modifier_type is None or modifier_type in modifier_behavior)
            )

            if should_split:
                # Clean up value string (strip wildcards artifacts)
                clean_val = value_str
                if modifier_type in ["SigmaEndswithModifier", "SigmaContainsModifier"] and clean_val.startswith("*"):
                    clean_val = clean_val[1:]
                if modifier_type in ["SigmaStartswithModifier", "SigmaContainsModifier"] and clean_val.endswith("*"):
                    clean_val = clean_val[:-1]

                parts = clean_val.replace("/", "\\").rsplit("\\", 1)
                
                if len(parts) == 2:
                    folder_part, file_part = parts
                    
                    items = []
                    folder_action, file_action = modifier_behavior.get(modifier_type, (None, None))
                    
                    # Helper to get modifiers
                    def get_mods(action):
                        return detection_item.modifiers if action == "keep" else []

                    if folder_part:
                        items.append(SigmaDetectionItem("FolderPath", get_mods(folder_action), [SigmaString(folder_part)]))
                    
                    if file_part:
                        items.append(SigmaDetectionItem("FileName", get_mods(file_action), [SigmaString(file_part)]))
                    
                    if items:
                        detections.append(SigmaDetection(items))
                        continue

            # Fallback: Map to FileName with original modifiers, stripping leading slashes
            if isinstance(val, SigmaString):
                # Extract string parts, strip leading slashes, rejoin
                string_parts = ''.join(p for p in val.s if isinstance(p, str))
                cleaned = string_parts.lstrip('\\').lstrip('/')
            else:
                cleaned = value_str.lstrip('\\').lstrip('/')
            
            detections.append(SigmaDetection([
                SigmaDetectionItem("FileName", detection_item.modifiers, [SigmaString(cleaned)])
            ]))
        
        return SigmaDetection(detections)


class XDRHashesValuesTransformation(BaseHashesValuesTransformation):
    """
    Transforms the Hashes field in XDR Tables to create fields for each hash algorithm.
    """

    def __init__(self):
        super().__init__(valid_hash_algos=["MD5", "SHA1", "SHA256"], field_prefix="")


class PipeNameTransformation(DetectionItemTransformation):
    """Transform PipeName field to use SanitizedPipeName for DeviceEvents.
    
    For pipe_created category, PipeName in Sigma rules needs to map to SanitizedPipeName
    which is created via: 
    | extend SanitizedPipeName = replace_regex(tostring(parse_json(AdditionalFields).PipeName), @"^\\\\Device\\\\(NamedPipe\\\\(LOCAL\\\\|GLOBAL\\\\)?|Mup\\\\[a-zA-Z0-9-_.]*\\\\(pipe|PIPE)\\\\)", "")
    
    This transformation:
    - Strips leading backslashes from PipeName values (since SanitizedPipeName has the prefix removed)
    - Maps the field to "SanitizedPipeName"
    """

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        # Strip leading backslashes from all values
        cleaned_values = []
        for val in detection_item.value:
            if isinstance(val, SigmaString):
                # Get the plain string value and strip leading backslashes
                plain_value = val.to_plain()
                cleaned_value = plain_value.lstrip('\\')
                # Create new SigmaString with cleaned value
                cleaned_values.append(SigmaString(cleaned_value))
            else:
                cleaned_values.append(val)
        
        # Return detection item with SanitizedPipeName field
        return SigmaDetectionItem(
            field="SanitizedPipeName",
            modifiers=detection_item.modifiers,
            value=cleaned_values
        )


class ImageToOriginalFileNameTransformation(DetectionItemTransformation):
    """
    Custom DetectionItemTransformation to map Image to Image OR OriginalFileName.
    This allows matching against the original filename even if the file was renamed.
    It extracts the filename from the Image path and uses it for OriginalFileName.
    """

    def apply_detection_item(
        self, detection_item: SigmaDetectionItem
    ) -> Optional[Union[SigmaDetection, SigmaDetectionItem]]:
        image_detection_item = detection_item
        
        # Create a new detection item for OriginalFileName
        original_filename_values = []
        for v in detection_item.value:
            # Extract filename from path
            filename = str(v.to_plain().split("\\")[-1].split("/")[-1])
            original_filename_values.append(SigmaString(filename))
            
        original_filename_detection_item = SigmaDetectionItem(
            field="OriginalFileName",
            modifiers=detection_item.modifiers,
            value=original_filename_values,
        )
        
        return SigmaDetection(detection_items=[image_detection_item, original_filename_detection_item], item_linking=ConditionOR)
