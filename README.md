# pySigma Kusto Query Language (KQL) Backend

![Tests](https://github.com/AttackIQ/pySigma-backend-microsoft365defender/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/slincoln-aiq/9c0879725c7f94387801390bbb0ac8d6/raw/slincoln-aiq-pySigma-backend-microsoft365defender.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)
![PyPI version](https://badge.fury.io/py/pysigma-backend-kusto.svg)
![Python versions](https://img.shields.io/pypi/pyversions/pysigma-backend-kusto.svg)
![pySigma version](https://img.shields.io/badge/pySigma-%5E1.0.0-blue)
![License](https://img.shields.io/github/license/AttackIQ/pySigma-backend-microsoft365defender.svg)

## Contents

- [pySigma Kusto Query Language (KQL) Backend](#pysigma-kusto-query-language-kql-backend)
  - [📖 Overview](#-overview)
    - [🔑 Key Features](#-key-features)
    - [🧑‍💻 Maintainer](#-maintainer)
  - [🚀 Quick Start](#-quick-start)
  - [📘 Usage](#-usage)
    - [🖥️ sigma-cli](#️-sigma-cli)
    - [🐍 Python Script](#-python-script)
  - [🛠️ Advanced Features](#️-advanced-features)
    - [🔄 Pipeline \& Backend Args (New in 0.2.0)](#-pipeline--backend-args-new-in-020)
    - [🗃️ Custom Table Names (New in 0.3.0) (Beta)](#️-custom-table-names-new-in-030-beta)
  - [🔄 Processing Pipelines](#-processing-pipelines)
    - [📊 Rule Support](#-rule-support)
    - [🖥️ Commonly Supported Categories](#️-commonly-supported-categories)
  - [🧪 Custom Transformations](#-custom-transformations)
    - [📊 Custom Postprocessing Item](#-custom-postprocessing-item)
  - [❓Frequently Asked Questions](#frequently-asked-questions)
    - [How do I set the table name for a rule?](#how-do-i-set-the-table-name-for-a-rule)
    - [How do I set the table name for a rule in YAML?](#how-do-i-set-the-table-name-for-a-rule-in-yaml)
    - [How is the table name determined for a rule?](#how-is-the-table-name-determined-for-a-rule)
    - [How are field mappings determined for a rule?](#how-are-field-mappings-determined-for-a-rule)
    - [What tables are supported for each pipeline?](#what-tables-are-supported-for-each-pipeline)
    - [I am receiving an `Invalid SigmaDetectionItem field name encountered` error. What does this mean?](#i-am-receiving-an-invalid-sigmadetectionitem-field-name-encountered-error-what-does-this-mean)
    - [My query\_table or custom field mapping isn't working](#my-query_table-or-custom-field-mapping-isnt-working)
  - [👨‍💻 Developer Guide](#-developer-guide)
    - [Factory Pattern for ProcessingItems (v1.0+)](#factory-pattern-for-processingitems-v10)
  - [🤝 Contributing](#-contributing)
  - [📄 License](#-license)

## 📖 Overview

The **pySigma Kusto Backend** transforms Sigma Rules into queries using [Kusto Query Language (KQL)](https://learn.microsoft.com/en-us/kusto/query/?view=microsoft-fabric). This backend supports multiple Microsoft products, including:

- [Microsoft XDR Advanced Hunting Queries](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview) (Formally Microsoft 365 Defender Advanced Hunting Queries)
- [Azure Sentinel Advanced Security Information Model (ASIM) Queries](https://learn.microsoft.com/en-us/azure/sentinel/normalization)
- [Azure Monitor Queries](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/get-started-queries)

> **Note:** This backend was previously named **pySigma Microsoft 365 Defender Backend**.

### 🔑 Key Features

- **Backend**: `sigma.backends.kusto` with `KustoBackend` class
- **Pipelines**: Provides `microsoft_xdr_pipeline`, `sentinelasim_pipeline`, and `azure_monitor_pipeline` for query tables and field renames
- **Output**: Query strings in Kusto Query Language (KQL)
- **pySigma v1.0.0+**: Fully compatible with pySigma v1.0.0+ using factory pattern for pipeline objects
- **Correlation Rules**: Supports all Sigma correlation rules

### 🧑‍💻 Maintainer

- [Stephen Lincoln](https://github.com/slincoln-aiq) via [AttackIQ](https://github.com/AttackIQ)

## 🚀 Quick Start

1. Install the package:

   ```bash
   pip install pysigma-backend-kusto
   ```

   > **Note:** This package requires `pySigma` version 1.0.0 or higher and Python 3.10+.

2. Convert a Sigma rule to MIcrosoft XDR KQL query using sigma-cli:

   ```bash
   sigma convert -t kusto -p microsoft_xdr path/to/your/rule.yml
   ```

3. Or use in a Python script:

   ```python
   from sigma.rule import SigmaRule

   from sigma.backends.kusto import KustoBackend
   from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

   # Load your Sigma rule
   rule = SigmaRule.from_yaml(
      """
      title: Mimikatz CommandLine
      status: test
      logsource:
            category: process_creation
            product: windows
      detection:
            sel:
               CommandLine|contains: mimikatz.exe
            condition: sel
      """
   )

   # Convert the rule
   xdr_pipeline = microsoft_xdr_pipeline()
   backend = KustoBackend(processing_pipeline=xdr_pipeline)
   print(backend.convert_rule(rule)[0])

   ```

## 📘 Usage

### 🖥️ sigma-cli

Use with `sigma-cli` per [typical sigma-cli usage](https://github.com/SigmaHQ/sigma-cli#usage):

```bash
sigma convert -t kusto -p microsoft_xdr -f default -s ~/sigma/rules
```

### 🐍 Python Script

Use the backend and pipeline in a standalone Python script. The pipeline is passed to the backend during initialization.

```python
from sigma.rule import SigmaRule
from sigma.backends.kusto import KustoBackend
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

# Define an example rule as a YAML str
sigma_rule = SigmaRule.from_yaml("""
  title: Mimikatz CommandLine
  status: test
  logsource:
      category: process_creation
      product: windows
  detection:
      sel:
          CommandLine|contains: mimikatz.exe
      condition: sel
""")

# Create pipeline and backend
# Note: In pySigma v1.0+, the pipeline is initialized once and passed to the backend
pipeline = microsoft_xdr_pipeline()
kusto_backend = KustoBackend(processing_pipeline=pipeline)

# Convert the rule
print(sigma_rule.title + " KQL Query: \n")
print(kusto_backend.convert_rule(sigma_rule)[0])
```

Output:

```text
Mimikatz CommandLine KQL Query: 

DeviceProcessEvents
| where ProcessCommandLine contains "mimikatz.exe"
```

## 🛠️ Advanced Features

### 🔄 Pipeline & Backend Args (New in 0.2.0)

For the `microsoft_xdr_pipeline`:

- `transform_parent_image`: Controls ParentImage field mapping behavior
  - When set to `True` (default), maps ParentImage to InitiatingProcessParentFileName
  - When set to `False`, maps ParentImage to InitiatingProcessFileName
  - Useful for adjusting field mappings based on specific rule requirements
  - Example usage:

```python
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
pipeline = microsoft_xdr_pipeline(transform_parent_image=False)
```

This argument allows fine-tuning of the ParentImage field mapping, which can be crucial for accurate rule conversion in certain scenarios. By default, it follows the behavior of mapping ParentImage to the parent process name, but setting it to `False` allows for mapping to the initiating process name instead.

### ⏱️ Custom Timestamp Field

Correlation rules use `bin(<timestamp_field>, <timespan>)` in their aggregation expressions. The timestamp field name differs depending on the target platform:

| Pipeline | Timestamp field |
|---|---|
| `microsoft_xdr` | `Timestamp` |
| `sentinelasim`, `azure_monitor`, none | `TimeGenerated` |

This is set automatically when using the built-in pipelines. If you write a **custom YAML pipeline**, add a `set_state` transformation to declare the correct field:

```yaml
transformations:
  - id: set_timestamp_field
    type: set_state
    key: timestamp_field
    val: "TimeGenerated"   # or "Timestamp" for XDR
```

If no `timestamp_field` is set by any pipeline, the backend falls back to `Timestamp`.

### 🗃️ Custom Table Names (New in 0.3.0) (Beta)

The `query_table` argument allows users to override table mappings and set custom table names.  This is useful for converting Sigma rules where the rule category does not easily map to the default table names.

#### YAML Pipelines

To set a custom table name, ensure your pipeline has a priority of 9 or lower, as sigma-cli merges pipelines based on priority (default is 10). Field mappings in `mappings.py` will apply according to your specified table name, along with any custom field mapping transformations.

```YAML
# test_table_name_pipeline.yml
name: Custom Query Table Pipeline
priority: 1
transformations:
- id: test_name_name
  type: set_state
  key: "query_table"
  val: ["DeviceProcessEvents"]
```

```bash
sigma convert -t kusto -p microsoft_xdr -p test_table_name_pipeline.yml test_rule.yml
```

#### Python Pipelines

You can also set the table name in the pipeline via Python by passing the `query_table` parameter to the pipeline.

```python
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
my_pipeline = microsoft_xdr_pipeline(query_table="DeviceProcessEvents")
```

## 🔄 Processing Pipelines

This project includes three main processing pipelines, each designed for a specific Microsoft product:

1. **Microsoft XDR Pipeline** (formerly Microsoft 365 Defender)
   - Status: Production-ready
   - Supports a wide range of Sigma rule categories
   - All tables supported, but additional field mapping contributions welcome

2. **Sentinel ASIM Pipeline**
   - Status: Beta
   - Transforms rules for Microsoft Sentinel Advanced Security Information Model (ASIM)
   - All tables supported, but field mappings are limited

3. **Azure Monitor Pipeline**
   - Status: Alpha
   - Currently supports field mappings for `SecurityEvent` and `SigninLogs` tables only
   - All tables supported, but requires custom field mappings for other tables

Each pipeline includes a `query_table` parameter for setting custom table names.

### 📊 Rule Support

Rules are supported if either:

- A valid table name is supplied via the `query_table` parameter or YAML pipeline
- The rule's logsource category is supported and mapped in the pipeline's `mappings.py` file
- The rule has an `EventID` or `EventCode` field in the `detection` section, and the eventid is present in the pipeline's `eventid_to_table_mappings` dictionary

#### Correlation Rule Support

This backend supports all Sigma [correlation rules](https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md#correlation-types):

| Correlation type | KQL aggregation |
|---|---|
| `event_count` | `summarize EventCount = count() by bin(<timestamp>, <timespan>)` |
| `value_count` | `summarize ValueCount = count_distinct(<field>) by bin(<timestamp>, <timespan>)` |
| `value_avg` | `summarize ValueAvg = avg(<field>) by bin(<timestamp>, <timespan>)` |
| `value_median` | `summarize ValueMedian = percentile(<field>, 50) by bin(<timestamp>, <timespan>)` |
| `value_sum` | `summarize ValueSum = sum(<field>) by bin(<timestamp>, <timespan>)` |
| `value_percentile` | `summarize ValuePercentile = percentile(<field>, <p>) by bin(<timestamp>, <timespan>)` |
| `temporal` | `summarize TemporalCount = count_distinct(EventType) by bin(<timestamp>, <timespan>)` |
| `temporal_ordered` | `summarize TemporalCount = count_distinct(EventType), <order_aggs> by bin(<timestamp>, <timespan>)` |

Multi-rule correlations union the referenced sub-queries with `union`. The timestamp field used in `bin()` is set automatically by each pipeline (see [Custom Timestamp Field](#️-custom-timestamp-field) above).

### 🖥️ Commonly Supported Categories

- process_creation
- image_load
- network_connection
- file_access, file_change, file_delete, file_event, file_rename
- registry_add, registry_delete, registry_event, registry_set

Specific pipelines may support additional categories. Check each pipeline's `mappings.py` file for details.

## 🧪 Custom Transformations

This package includes several custom `ProcessingPipeline` `Transformation` classes:

1. **DynamicFieldMappingTransformation**
   - Determines field mappings based on the `query_table` state parameter

2. **GenericFieldMappingTransformation**
   - Applies common field mappings across all tables in a pipeline

3. **BaseHashesValuesTransformation**
   - Transforms the Hashes field, removing hash algorithm prefixes

4. **ParentImageValueTransformation**
   - Extracts parent process name from Sysmon ParentImage field

5. **SplitDomainUserTransformation**
   - Splits User field into separate domain and username fields

6. **RegistryActionTypeValueTransformation**
   - Adjusts registry ActionType values for compatibility

7. **InvalidFieldTransformation**
   - Identifies unsupported or invalid fields in rules

8. **SetQueryTableStateTransformation**
   - Manages the `query_table` state based on rule category or custom settings

### 📊 Custom Postprocessing Item

1. **PrependQueryTablePostprocessingItem**

- Adds table name as prefix to each query in a SigmaCollection, or single query in a SigmaRule

## ❓Frequently Asked Questions

### How do I set the table name for a rule?

You can set the table name for a rule by adding the `query_table` parameter to the pipeline and setting it to the table name you want to use.

```python
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
pipeline = microsoft_xdr_pipeline(query_table="DeviceProcessEvents")
```

### How do I set the table name for a rule in YAML?

You can set the table name for a rule in YAML by adding the `query_table` parameter to the pipeline and setting it to the table name you want to use.

```YAML
# test_table_name_pipeline.yml
name: 
priority: 1
transformations:
- id: test_name_name
  type: set_state
  key: "query_table"
  val: ["DeviceProcessEvents"]
```

```bash
sigma convert -t kusto -p microsoft_xdr -p test_table_name_pipeline.yml test_rule.yml
```

### How is the table name determined for a rule?

The table name is set by the `SetQueryTableStateTransformation` transformation, which is the first transformation in each pipeline. The `query_table` is set to the pipeline's `state` parameter with the following priority:
1. The `query_table` parameter passed to the pipeline, if using a Python script/code.
2. The `query_table` parameter passed to the pipeline in a custom YAML pipeline, if using sigma-cli.
3. The `logsource.category` field in the rule, if the category is present in the pipeline's `category_to_table_mappings` dictionary.
4. The `EventID` or `EventCode` field, if present in the rule's `detection` section, and if the eventid is present in the pipeline's `eventid_to_table_mappings` dictionary.
5. If none of the above are present, an error is raised.

### How are field mappings determined for a rule?

The field mappings are determined by the `DynamicFieldMappingTransformation` transformation. It will use the table name from the pipeline state's `query_table` key.  The field mapping logic is defined in each pipeline's `mappings.py` file for each table.  If a field is not found in the table, the `GenericFieldMappingTransformation` will apply generic field mappings.  If a field is not found in the generic field mappings, the field will be kept the same.

### What tables are supported for each pipeline?

The tables that are supported for each pipeline are defined in each pipeline's `tables.py` file. This file is automatically generated by the scripts in the `utils` folder. These scripts pull documentation from Microsoft to get all documented tables and their fields and schema.

### I am receiving an `Invalid SigmaDetectionItem field name encountered` error. What does this mean?

This error means that the field name(s) provided in the error are not found in the tables fields defined in `tables.py` for the pipeline you are using. This probably means that a Sigma rule's field was not found in the field mappings for the table.  To fix this error, you can supply your own custom field mappings to convert the unsupported field into a supported one. For example, in using YAML:

```YAML
# custom_field_mapping_pipeline.yml
name: Custom Field Mapping
priority: 1
transformations:
- id: field_mapping
    type: field_name_mapping
    mapping:
        MyNotSupportedField: a_supported_field
    rule_conditions:
    - type: logsource
        service: sysmon
```

```bash
sigma convert -t kusto -p custom_field_mapping_pipeline.yml -p microsoft_xdr test_rule.yml
```

If you find the field mapping useful, please consider submitting a PR to add it to the pipeline's field mappings :)

### My query_table or custom field mapping isn't working

Each pipeline in the project has a priority of 10. If you are trying to set the table name or custom field mappings, your pipeline needs to have a priority of 9 or less.  You can set the priority in the YAML pipeline like so:

```YAML
# test_table_name_pipeline.yml
name:
priority: 9
transformations:
- id: test_name_name
  type: set_state
  key: "query_table"
  val: ["DeviceProcessEvents"]
```

## 👨‍💻 Developer Guide

### Factory Pattern for ProcessingItems (v1.0+)

**Background**: pySigma v1.0.0 introduced [Breaking Change #12](https://github.com/SigmaHQ/pySigma/blob/main/docs/Breaking_Changes.rst#12-processingitem-reference-assignment), which states that `ProcessingItem`, `Transformation`, and condition class objects can only reference one pipeline instance. Reusing these objects across multiple pipeline instances causes errors.

**Solution**: This project uses the **factory pattern** to create fresh `ProcessingItem` instances for each pipeline.

#### Implementation

Instead of creating module-level `ProcessingItem` singletons (old v0.x pattern), we use factory functions that return new instances:

```python
# ❌ OLD (v0.x) - Module-level singleton (causes issues in v1.0+)
drop_fields_proc_item = ProcessingItem(
    identifier="azure_monitor_drop_fields",
    transformation=DropDetectionItemTransformation(),
    field_name_conditions=[IncludeFieldCondition(["ObjectType"])],
)

# ✅ NEW (v1.0+) - Factory function
def _create_drop_fields_item():
    """Drop ObjectType fields"""
    return ProcessingItem(
        identifier="azure_monitor_drop_fields",
        transformation=DropDetectionItemTransformation(),
        field_name_conditions=[IncludeFieldCondition(["ObjectType"])],
    )
```

#### Pipeline Construction

Pipeline functions call factory functions to build fresh processing items:

```python
def microsoft_xdr_pipeline(query_table: Optional[str] = None) -> ProcessingPipeline:
    """Creates a new Microsoft XDR pipeline with fresh ProcessingItems."""
    return ProcessingPipeline(
        name="Microsoft XDR Pipeline",
        priority=10,
        items=[
            _create_set_query_table_item(query_table),  # Factory call
            _create_drop_eventid_item(),                 # Factory call
            _create_fieldmappings_item(),                # Factory call
            # ... more factory calls
        ],
    )
```

#### Guidelines for Contributors

When adding new `ProcessingItem` instances to pipelines:

1. **Create a factory function** with a descriptive name starting with `_create_`
2. **Add a docstring** explaining what the processing item does
3. **Return a new ProcessingItem instance** each time the function is called
4. **Call the factory function** in the main pipeline function
5. **Never reuse** `ProcessingItem` objects across pipeline calls

**Example**:

```python
def _create_my_custom_transformation_item():
    """Applies custom field transformation for XYZ table."""
    return ProcessingItem(
        identifier="my_custom_transformation",
        transformation=MyCustomTransformation(),
        rule_conditions=[LogsourceCondition(category="my_category")],
    )

def my_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="My Pipeline",
        priority=10,
        items=[
            _create_my_custom_transformation_item(),  # Fresh instance
        ],
    )
```

This pattern ensures:
- ✅ Each pipeline instance gets fresh `ProcessingItem` objects
- ✅ Multiple backend instances can coexist without conflicts
- ✅ State management works correctly across rule conversions
- ✅ Tests can create multiple pipeline instances without issues

For more details, see the [pySigma v1.0.0 Breaking Changes documentation](https://github.com/SigmaHQ/pySigma/blob/main/docs/Breaking_Changes.rst).

## 🤝 Contributing

Contributions are welcome, especially for table and field mappings! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

Please make sure to update tests as appropriate.

## 📄 License

This project is licensed under the GNU Lesser General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
