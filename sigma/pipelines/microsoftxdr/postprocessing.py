from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import QueryPostprocessingItem
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule

# Postprocessing for pipe_created to add extend clause for SanitizedPipeName
class AddPipeNameExtendPostprocessing(QueryPostprocessingTransformation):
    """Add extend clause to create SanitizedPipeName column for pipe_created queries.
    
    This transformation runs AFTER PrependQueryTablePostprocessingItem, so the query
    already has the table name and '| where' clause. We need to:
    1. Keep the ActionType filter in the where clause (for performance)
    2. Add the extend clause after the ActionType filter
    3. Add the rest of the conditions after the extend
    """
    
    def apply(self, rule: SigmaRule, query: str) -> str:  # type: ignore # noqa: F821
        extend_clause = '| extend SanitizedPipeName = replace_regex(tostring(parse_json(AdditionalFields).PipeName), @"^\\\\Device\\\\(NamedPipe\\\\(LOCAL\\\\|GLOBAL\\\\)?|Mup\\\\[a-zA-Z0-9-_.]*\\\\(pipe|PIPE)\\\\)", "")'

        # Check if this is a pipe_created rule
        if rule.logsource.category == "pipe_created":
            # Query format at this point: "DeviceEvents\n| where ActionType =~ "NamedPipeEvent" and {other_conditions}"
            # We need to insert the extend clause after ActionType filter but before other conditions
            lines = query.split('\n', 1)
            if len(lines) == 2:
                table_name = lines[0]
                where_clause = lines[1]  # "| where ActionType =~ "NamedPipeEvent" and {other_conditions}"
                
                # Split the where clause to separate ActionType from other conditions
                if 'ActionType =~ "NamedPipeEvent"' in where_clause:
                    # Split at the ActionType condition
                    if ' and ' in where_clause:
                        # There are additional conditions after ActionType
                        parts = where_clause.split(' and ', 1)
                        actiontype_part = parts[0]  # "| where ActionType =~ "NamedPipeEvent""
                        rest_conditions = parts[1]  # remaining conditions
                        return f'{table_name}\n{actiontype_part}\n{extend_clause}\n| where {rest_conditions}'
                    else:
                        # Only ActionType condition, no other conditions
                        return f'{table_name}\n{where_clause}\n{extend_clause}'
        return query


def create_add_pipe_name_extend_item():
    """Add extend clause to create SanitizedPipeName column for pipe_created queries."""
    return QueryPostprocessingItem(
        identifier="microsoft_xdr_pipe_created_extend",
        transformation=AddPipeNameExtendPostprocessing(),
        rule_conditions=[LogsourceCondition(category="pipe_created")],
    )
