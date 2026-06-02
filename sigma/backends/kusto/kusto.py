import re
from collections import Counter
from typing import ClassVar, Dict, Optional, Pattern, Tuple, Type, Union

from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionItem, ConditionNOT, ConditionOR
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationConditionOperator, SigmaCorrelationRule
from sigma.types import SigmaCompareExpression, SigmaNumber, SigmaString, SpecialChars


class KustoBackend(TextQueryBackend):
    """Microsoft 365 Defender KQL Backend."""

    # The backend generates grouping if required
    name: ClassVar[str] = "Kusto backend"
    identifier: ClassVar[str] = "kusto"
    formats: Dict[str, str] = {
        "default": "Kusto Query Language search strings",
    }

    requires_pipeline: bool = False  # m365 pipeline is automatically applied

    # Operator precedence
    parenthesize = True
    precedence: ClassVar[Tuple[Type[ConditionItem], Type[ConditionItem], Type[ConditionItem]]] = (
        ConditionNOT,
        ConditionAND,
        ConditionOR,
    )
    group_expression: ClassVar[str] = (
        "({expr})"  # Expression for precedence override grouping as format string with {expr} placeholder
    )
    # Generated query tokens
    token_separator: str = " "  # separator inserted between all boolean operators
    or_token: ClassVar[str] = "or"
    and_token: ClassVar[str] = "and"
    not_token: ClassVar[str] = "not"
    eq_token: ClassVar[str] = " =~ "  # Token inserted between field and value (without separator)

    # String output
    ## Fields
    ### Quoting
    field_quote: ClassVar[str] = (
        "'"  # Character used to quote field characters if field_quote_pattern matches (or not, depending on field_quote_pattern_negation). No field name quoting is done if not set.
    )
    field_quote_pattern: ClassVar[Pattern] = re.compile(
        "^\\w+$"
    )  # Quote field names if this pattern (doesn't) matches, depending on field_quote_pattern_negation. Field name is always quoted if pattern is not set.
    field_quote_pattern_negation: ClassVar[bool] = (
        True  # Negate field_quote_pattern result. Field name is quoted if pattern doesn't matches if set to True (default).
    )

    ### Escaping
    field_escape: ClassVar[str] = ""  # Character to escape particular parts defined in field_escape_pattern.
    field_escape_quote: ClassVar[bool] = True  # Escape quote string defined in field_quote
    field_escape_pattern: ClassVar[Pattern] = re.compile(
        "\\s"
    )  # All matches of this pattern are prepended with the string contained in field_escape.

    ## Values
    str_quote: ClassVar[str] = '"'  # string quoting character (added as escaping character)
    escape_char: ClassVar[str] = "\\"  # Escaping character for special characters inside string
    wildcard_multi: ClassVar[str] = "*"  # Character used as multi-character wildcard
    wildcard_single: ClassVar[str] = "*"  # Character used as single-character wildcard
    add_escaped: ClassVar[str] = "\\"  # Characters quoted in addition to wildcards and string quote
    filter_chars: ClassVar[str] = ""  # Characters filtered
    bool_values: ClassVar[Dict[bool, str]] = {  # Values to which boolean values are mapped.
        True: "true",
        False: "false",
    }

    # String matching operators. if none is appropriate eq_token is used.
    startswith_expression: ClassVar[str] = "{field} startswith {value}"
    endswith_expression: ClassVar[str] = "{field} endswith {value}"
    contains_expression: ClassVar[str] = "{field} contains {value}"
    wildcard_match_expression: ClassVar[Union[str, None]] = (
        '{field} matches regex "{regex}"'  # Regular expression for wildcard matching when direct equality is not applicable. Fixes #34 if not as_in (logic implemented in convert_condition_as_in_expression)
    )

    # Regular expressions
    re_expression: ClassVar[str] = (
        '{field} matches regex "{regex}"'  # Regular expression query as format string with placeholders {field} and {regex}
    )
    re_escape_char: ClassVar[str] = "\\"  # Character used for escaping in regular expressions
    re_escape: ClassVar[Tuple[str, ...]] = '"'  # List of strings that are escaped
    re_escape_escape_char: bool = True  # If True, the escape character is also escaped

    # cidr expressions
    cidr_wildcard: ClassVar[str] = "*"  # Character used as single wildcard
    cidr_expression: ClassVar[str] = (
        'ipv4_is_in_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = {value}
    )
    cidr_in_list_expression: ClassVar[str] = (
        'ipv4_is_in_any_range({field}, "{value}")'  # CIDR expression query as format string with placeholders {field} = in({list})
    )

    # Numeric comparison operators
    compare_op_expression: ClassVar[str] = (
        "{field} {operator} {value}"  # Compare operation query as format string with placeholders {field}, {operator} and {value}
    )
    # Mapping between CompareOperators elements and strings used as replacement for {operator} in compare_op_expression
    compare_operators: ClassVar[Dict[object, str]] = {
        SigmaCompareExpression.CompareOperators.LT: "<",
        SigmaCompareExpression.CompareOperators.LTE: "<=",
        SigmaCompareExpression.CompareOperators.GT: ">",
        SigmaCompareExpression.CompareOperators.GTE: ">=",
    }

    # Null/None expressions
    field_null_expression: ClassVar[str] = (
        "isnull({field})"  # Expression for field has null value as format string with {field} placeholder for field name
    )
    field_exists_expression: ClassVar[str] = (
        "isnotempty({field})"  # Expression for field exists as format string with {field} placeholder for field name
    )
    field_not_exists_expression: ClassVar[str] = (
        "isempty({field})"  # Expression for field does not exist as format string with {field} placeholder for field name
    )

    # Field value in list, e.g. "field in (value list)" or "field containsall (value list)"
    convert_or_as_in: ClassVar[bool] = True  # Convert OR as in-expression
    convert_and_as_in: ClassVar[bool] = True  # Convert AND as in-expression
    in_expressions_allow_wildcards: ClassVar[bool] = (
        True  # Values in list can contain wildcards. If set to False (default) only plain values are converted into in-expressions.
    )
    field_in_list_expression: ClassVar[str] = (
        "{field} {op} ({list})"  # Expression for field in list of values as format string with placeholders {field}, {op} and {list}
    )
    or_in_operator: ClassVar[str] = (
        "in~"  # Operator used to convert OR into in-expressions. Must be set if convert_or_as_in is set
    )
    and_in_operator: ClassVar[str] = (
        "has_all"  # Operator used to convert AND into in-expressions. Must be set if convert_and_as_in is set
    )
    list_separator: ClassVar[str] = ", "  # List element separator

    # Value not bound to a field
    unbound_value_str_expression: ClassVar[str] = (
        "{value}"  # Expression for string value not bound to a field as format string with placeholder {value}
    )
    unbound_value_num_expression: ClassVar[str] = (
        "{value}"  # Expression for number value not bound to a field as format string with placeholder {value}
    )
    unbound_value_re_expression: ClassVar[str] = (
        "_=~{value}"  # Expression for regular expression not bound to a field as format string with placeholder {value}
    )

    # Query finalization: appending and concatenating deferred query part
    deferred_start: ClassVar[str] = "\n| "  # String used as separator between main query and deferred parts
    deferred_separator: ClassVar[str] = "\n| "  # String used to join multiple deferred query parts
    deferred_only_query: ClassVar[str] = "*"  # String used as query if final query only contains deferred expression

    # We use =~ for eq_token so everything is case insensitive. But this cannot be used with ints/numbers in queries
    # So we can define a new token to use for SigmaNumeric types and override convert_condition_field_eq_val_num
    # to use it
    num_eq_token: ClassVar[str] = " == "

    timestamp_field: ClassVar[str] = "Timestamp"  # Default timestamp field name, can be overridden by pipeline state

    timespan_mapping: ClassVar[Dict[str, str]] = {
        "s": "s",
        "m": "min",
        "h": "h",
        "d": "d",
    }

    # Correlation support

    correlation_methods: ClassVar[Dict[str, str]] = {
        "default": "Summarize with bin() - clock-aligned time buckets",
    }
    default_correlation_method: ClassVar[str] = "default"

    default_correlation_query: ClassVar[str] = {"default": "{search}\n{aggregate}\n{condition}"}

    correlation_search_single_rule_expression: ClassVar[str] = "{query}"

    # Multiple referenced rules
    correlation_search_multi_rule_expression: ClassVar[str] = "union\n{queries}"
    correlation_search_multi_rule_query_expression: ClassVar[str] = "(\n{query}\n)"
    correlation_search_multi_rule_query_expression_joiner: ClassVar[str] = ",\n"

    correlation_search_field_normalization_expression: ClassVar[str] = "| extend {alias} = {field}"
    correlation_search_field_normalization_expression_joiner: ClassVar[str] = "\n"

    # value_count correlation
    value_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize ValueCount = count_distinct({field}) by bin({timestamp}, {timespan}){groupby}"
    }

    value_count_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where ValueCount {op} {count}"}

    # value_avg correlation
    value_avg_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize ValueAvg = avg({field}) by bin({timestamp}, {timespan}){groupby}"
    }
    value_avg_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where ValueAvg {op} {count}"}

    # value_median correlation
    value_median_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize ValueMedian = percentile({field}, 50) by bin({timestamp}, {timespan}){groupby}"
    }

    value_median_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where ValueMedian {op} {count}"}

    # value_sum correlation
    value_sum_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize ValueSum = sum({field}) by bin({timestamp}, {timespan}){groupby}"
    }

    value_sum_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where ValueSum {op} {count}"}

    # value_percentile correlation
    value_percentile_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize ValuePercentile = percentile({field}, {percentile}) by bin({timestamp}, {timespan}){groupby}"
    }

    # event_count correlation
    event_count_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize EventCount = count() by bin({timestamp}, {timespan}){groupby}"
    }
    event_count_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where EventCount {op} {count}"}

    # temporal correlation
    temporal_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize TemporalCount = count_distinct(EventType) by bin({timestamp}, {timespan}){groupby}"
    }
    temporal_condition_expression: ClassVar[Dict[str, str]] = {"default": "| where TemporalCount {op} {count}"}

    # temporal_ordered correlation
    temporal_ordered_aggregation_expression: ClassVar[Dict[str, str]] = {
        "default": "| summarize TemporalCount = count_distinct(EventType), {order_aggs} by bin({timestamp}, {timespan}){groupby}"
    }

    # Override methods

    #  For numeric values, need == instead of =~
    def convert_correlation_temporal_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        """Override for temporal correlation.

        Tags each referenced-rule sub-query with its rule ID via ``| extend EventType``,
        unions them, then counts *distinct* event types per time bucket.  This matches the
        intended semantics: detect multiple different event types occurring close together
        in time (e.g. failed logon followed by successful logon from the same source).
        """
        subquery_parts = []
        for rule_ref in rule.referenced_rules:
            base_rule = rule_ref.rule
            rule_id = str(base_rule.name or base_rule.id)
            table = self._get_rule_table(base_rule)
            normalization = self.convert_correlation_search_field_normalization_expression(rule.aliases, rule_ref)
            auto_norm = self._build_groupby_normalization(rule, rule_ref)
            for query in base_rule.get_conversion_result():
                full_query = query
                if normalization:
                    full_query = f"{full_query}\n{normalization}"
                if auto_norm:
                    full_query = f"{full_query}\n{auto_norm}"
                if table and not full_query.lstrip().startswith(table):
                    full_query = f"{table}\n| where {full_query}"
                full_query = f'{full_query}\n| extend EventType = "{rule_id}"'
                subquery_parts.append(f"(\n{full_query}\n)")

        search = "union\n" + ",\n".join(subquery_parts)

        # Resolve group-by field names to the canonical (most-common) KQL column name
        groupby_fields = self._resolve_groupby_fields(rule)
        groupby = (", " + ", ".join(groupby_fields)) if groupby_fields else ""
        timespan = self._correlation_timespan_to_kql(rule.timespan)
        timestamp = self._get_timestamp_field()

        aggregate = self.temporal_aggregation_expression[method].format(
            timespan=timespan,
            groupby=groupby,
            timestamp=timestamp,
        )

        op_map = {
            SigmaCorrelationConditionOperator.GT: ">",
            SigmaCorrelationConditionOperator.GTE: ">=",
            SigmaCorrelationConditionOperator.LT: "<",
            SigmaCorrelationConditionOperator.LTE: "<=",
            SigmaCorrelationConditionOperator.EQ: "==",
        }
        op = op_map[rule.condition.op]
        condition = self.temporal_condition_expression[method].format(op=op, count=rule.condition.count)

        return [f"{search}\n{aggregate}\n{condition}"]

    def convert_correlation_temporal_ordered_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        """Override for ordered temporal correlation.

        Like the temporal correlation but adds an order check: each referenced rule's
        sub-query is tagged with both ``EventType`` and a 1-based ``EventOrder`` integer.
        The summarize step uses ``minif(Timestamp, EventOrder == N)`` to capture the
        first occurrence of each event type, and the condition appends
        ``FirstTs1 < FirstTs2 and FirstTs2 < FirstTs3 ...`` so that the events must
        have appeared in the declared rule order within the time window.
        """
        subquery_parts = []
        n_rules = len(rule.referenced_rules)
        for idx, rule_ref in enumerate(rule.referenced_rules, start=1):
            base_rule = rule_ref.rule
            rule_id = str(base_rule.name or base_rule.id)
            table = self._get_rule_table(base_rule)
            normalization = self.convert_correlation_search_field_normalization_expression(rule.aliases, rule_ref)
            auto_norm = self._build_groupby_normalization(rule, rule_ref)
            for query in base_rule.get_conversion_result():
                full_query = query
                if normalization:
                    full_query = f"{full_query}\n{normalization}"
                if auto_norm:
                    full_query = f"{full_query}\n{auto_norm}"
                if table and not full_query.lstrip().startswith(table):
                    full_query = f"{table}\n| where {full_query}"
                full_query = f'{full_query}\n| extend EventType = "{rule_id}", EventOrder = {idx}'
                subquery_parts.append(f"(\n{full_query}\n)")

        search = "union\n" + ",\n".join(subquery_parts)

        # Resolve group-by field names to the canonical (most-common) KQL column name
        groupby_fields = self._resolve_groupby_fields(rule)
        groupby = (", " + ", ".join(groupby_fields)) if groupby_fields else ""
        timespan = self._correlation_timespan_to_kql(rule.timespan)
        timestamp = self._get_timestamp_field()

        op_map = {
            SigmaCorrelationConditionOperator.GT: ">",
            SigmaCorrelationConditionOperator.GTE: ">=",
            SigmaCorrelationConditionOperator.LT: "<",
            SigmaCorrelationConditionOperator.LTE: "<=",
            SigmaCorrelationConditionOperator.EQ: "==",
        }
        op = op_map[rule.condition.op]

        # Build per-rule minif aggregations: FirstTs1 = minif(Timestamp, EventOrder == 1), ...
        order_aggs = ", ".join(f"FirstTs{i} = minif({timestamp}, EventOrder == {i})" for i in range(1, n_rules + 1))
        aggregate = self.temporal_ordered_aggregation_expression[method].format(
            order_aggs=order_aggs,
            timespan=timespan,
            groupby=groupby,
            timestamp=timestamp,
        )

        # Build ordering constraint: FirstTs1 < FirstTs2 and FirstTs2 < FirstTs3 ...
        order_conditions = " and ".join(f"FirstTs{i} < FirstTs{i + 1}" for i in range(1, n_rules))
        condition = self.temporal_condition_expression[method].format(op=op, count=rule.condition.count)
        if order_conditions:
            condition += f" and {order_conditions}"

        return [f"{search}\n{aggregate}\n{condition}"]

    def convert_condition_field_eq_val_num(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = number value expressions"""
        try:
            return self.escape_and_quote_field(cond.field) + self.num_eq_token + str(cond.value)
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Field equals numeric value expressions are not supported by the backend.")

    def convert_condition_as_in_expression(
        self, cond: Union[ConditionOR, ConditionAND], state: ConversionState
    ) -> Union[str, DeferredQueryExpression]:
        """Overridden method for conversion of field in value list conditions.
        KQL doesn't really use wildcards, so if we have an 'as_in' condition where one or more of the values has a wildcard,
        we can still use the as_in condition, then append on the wildcard value(s) with a startswith, endswith, or contains
        expression
        """

        field = self.escape_and_quote_field(cond.args[0].field)  # type: ignore
        op1 = self.or_in_operator if isinstance(cond, ConditionOR) else self.and_in_operator
        op2 = self.or_token if isinstance(cond, ConditionOR) else self.and_token
        list_nonwildcard = self.list_separator.join(
            [
                self.convert_value_str(arg.value, state)
                for arg in cond.args
                if isinstance(arg, ConditionFieldEqualsValueExpression)
                and (
                    (isinstance(arg.value, SigmaString) and not arg.value.contains_special())
                    or (isinstance(arg.value, SigmaNumber))
                )
            ]
        )
        list_wildcards = [
            arg.value
            for arg in cond.args
            if isinstance(arg, ConditionFieldEqualsValueExpression)
            and isinstance(arg.value, SigmaString)
            and arg.value.contains_special()
        ]
        as_in_expr = ""
        # Convert as_in and wildcard values separately
        if list_nonwildcard:
            as_in_expr = self.field_in_list_expression.format(field=field, op=op1, list=list_nonwildcard)
        wildcard_exprs_list = []
        if list_wildcards:
            for arg in list_wildcards:
                new_cond = ConditionFieldEqualsValueExpression(field=field, value=arg)
                if arg[1:-1].contains_special():  # Wildcard in string, not at start or end.
                    # We need to get rid of all wildcards, and create a 'and contains' for each element in the list
                    expr = f"{self.token_separator}{self.and_token}{self.token_separator}".join(
                        [
                            self.contains_expression.format(
                                field=field, value=self.convert_value_str(SigmaString(str(x)), state)
                            )
                            for x in arg.s
                            if not isinstance(x, SpecialChars)
                        ]
                    )
                    expr = self.group_expression.format(expr=expr)
                else:
                    expr = self.convert_condition_field_eq_val_str(new_cond, state)
                wildcard_exprs_list.append(expr)
        wildcard_exprs = f"{self.token_separator}{op2}{self.token_separator}".join(wildcard_exprs_list)
        if as_in_expr and wildcard_exprs:
            return as_in_expr + self.token_separator + op2 + self.token_separator + wildcard_exprs
        return as_in_expr + wildcard_exprs

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of NOT conditions. Overridden to surround the group or expr of the 'not' negation with parens,
        as expected by KQL.
        """
        arg = cond.args[0]
        try:
            if arg.__class__ in self.precedence:  # group if AND or OR condition is negated
                return self.not_token + "(" + str(self.convert_condition_group(arg, state)) + ")"  # type: ignore
            else:
                expr = self.convert_condition(arg, state)  # type: ignore
                if isinstance(expr, DeferredQueryExpression):  # negate deferred expression and pass it to parent
                    return expr.negate()
                else:  # convert negated expression to string
                    return self.not_token + "(" + expr + ")"
        except TypeError:  # pragma: no cover
            raise NotImplementedError("Operator 'not' not supported by the backend")

    def convert_value_str(self, s: Union[SigmaString, SigmaNumber], state: ConversionState) -> str:
        """Convert a SigmaString into a plain string which can be used in query."""
        if not isinstance(s, SigmaString):
            s = SigmaString(str(s))
        converted = super().convert_value_str(s, state)
        # If we have a wildcard in a string, we need to un-escape it
        # See issue #13
        return re.sub(r"\\\*", r"*", converted)

    def convert_correlation_search(self, rule: SigmaCorrelationRule, **kwargs) -> str:
        """Override to include table names in multi-rule correlation sub-queries.
        For single-rule correlation, delegates to the base class and lets postprocessing
        prepend the table. For multi-rule correlation, each sub-query is self-contained
        with its table name so no top-level prefix is needed.
        """
        if len(rule.referenced_rules) <= 1:
            return super().convert_correlation_search(rule, **kwargs)

        subquery_parts = []
        for rule_ref in rule.referenced_rules:
            base_rule = rule_ref.rule
            queries = base_rule.get_conversion_result()
            table = self._get_rule_table(base_rule)
            normalization = self.convert_correlation_search_field_normalization_expression(rule.aliases, rule_ref)
            for query in queries:
                full_query = query
                if normalization:
                    full_query = f"{full_query}\n{normalization}"
                if table and not full_query.lstrip().startswith(table):
                    full_query = f"{table}\n| where {full_query}"
                subquery_parts.append(f"(\n{full_query}\n)")

        return "union\n" + ",\n".join(subquery_parts)

    def _get_rule_table(self, rule) -> Optional[str]:
        """Return the KQL table name for a base rule.

        Priority:
        1. ``rule._kusto_query_table`` — set by SetQueryTableStateTransformation (Python pipelines).
        2. active pipeline state ``query_table`` — set via YAML ``set_state`` transformations.
        """
        table = getattr(rule, "_kusto_query_table", None)
        if table is None:
            pipeline = getattr(self, "last_processing_pipeline", None)
            if pipeline is not None:
                table = pipeline.state.get("query_table")
        return table

    def _resolve_field_for_table(self, sigma_field: str, table: Optional[str], base_rule=None) -> str:
        """Return the KQL column name for *sigma_field* in the context of *table*.

        First checks DynamicFieldMappingTransformation (per-table mappings used by built-in
        pipelines).  Then falls back to flat FieldMappingTransformation items whose
        rule_conditions match *base_rule* (used by custom YAML pipelines).  Finally returns
        the original Sigma field name unchanged.
        """
        pipeline = getattr(self, "last_processing_pipeline", None)
        if pipeline is None:
            return sigma_field
        for item in pipeline.items:
            t = item.transformation
            # Table-aware mappings (DynamicFieldMappingTransformation from built-in pipelines)
            fm = getattr(t, "field_mappings", None)
            if fm is not None:
                if table:
                    mapped = fm.table_mappings.get(table, {}).get(sigma_field)
                    if mapped:
                        return mapped
                generic = fm.generic_mappings.get(sigma_field)
                if generic:
                    return generic
                continue
            # Flat mappings (FieldMappingTransformation from custom YAML pipelines)
            flat = getattr(t, "mapping", None)
            if flat and sigma_field in flat:
                if base_rule is None or item.match_rule_conditions(base_rule):
                    result = flat[sigma_field]
                    return result[0] if isinstance(result, list) else result
        return sigma_field

    def _reverse_resolve_field(self, kql_field: str, table: Optional[str], base_rule=None) -> Optional[str]:
        """Reverse-lookup: given a KQL column name, return the original Sigma field name.

        Checks table-specific mappings first, then generic mappings (built-in pipelines),
        then flat FieldMappingTransformation items matching *base_rule* (custom pipelines).
        Returns None if not found (the field may already be a raw KQL name).
        """
        pipeline = getattr(self, "last_processing_pipeline", None)
        if pipeline is None:
            return None
        for item in pipeline.items:
            t = item.transformation
            fm = getattr(t, "field_mappings", None)
            if fm is not None:
                if table:
                    rev = {v: k for k, v in fm.table_mappings.get(table, {}).items()}
                    if kql_field in rev:
                        return rev[kql_field]
                rev_generic = {v: k for k, v in fm.generic_mappings.items()}
                if kql_field in rev_generic:
                    return rev_generic[kql_field]
                continue
            flat = getattr(t, "mapping", None)
            if flat:
                if base_rule is None or item.match_rule_conditions(base_rule):
                    rev_flat = {v: k for k, v in flat.items() if not isinstance(v, list)}
                    if kql_field in rev_flat:
                        return rev_flat[kql_field]
        return None

    def _resolve_groupby_fields(self, rule: "SigmaCorrelationRule") -> list:  # type: ignore[name-defined]
        """Return the list of KQL column names to use in the summarize group-by clause.

        For aliased fields the alias name is used as-is.  For un-aliased fields we pick the
        most-common KQL mapped name across all referenced rules so the name matches what
        _build_groupby_normalization emits.
        """
        if not rule.group_by:
            return []
        aliased_fields = {alias.alias for alias in rule.aliases}
        result = []
        first_ref = rule.referenced_rules[0] if rule.referenced_rules else None
        for kql_field in rule.group_by:
            if kql_field in aliased_fields:
                result.append(kql_field)
                continue
            first_table = self._get_rule_table(first_ref.rule) if first_ref else None
            first_rule = first_ref.rule if first_ref else None
            sigma_field = self._reverse_resolve_field(kql_field, first_table, first_rule) or kql_field
            mapped_names = [
                self._resolve_field_for_table(sigma_field, self._get_rule_table(rr.rule), rr.rule)
                for rr in rule.referenced_rules
            ]
            canonical = Counter(mapped_names).most_common(1)[0][0]
            result.append(canonical)
        return result

    def _build_groupby_normalization(self, rule: "SigmaCorrelationRule", rule_ref) -> str:  # type: ignore[name-defined]
        """Return ``| extend`` lines that normalize group-by fields whose KQL column name
        differs across the referenced rules.

        For each un-aliased group-by field (already pipeline-mapped to a KQL name):
          1. Reverse-resolve to the original Sigma field name.
          2. Forward-resolve per referenced rule's table, using rule conditions for flat mappings.
          3. Pick the most-common mapped name as the canonical column name.
          4. Emit ``| extend <canonical> = <actual>`` for rules where actual != canonical.
        """
        if not rule.group_by:
            return ""

        aliased_fields = {alias.alias for alias in rule.aliases}
        base_rule = rule_ref.rule
        table = self._get_rule_table(base_rule)
        first_ref = rule.referenced_rules[0] if rule.referenced_rules else None

        extends = []
        for kql_field in rule.group_by:
            if kql_field in aliased_fields:
                continue  # alias machinery handles this already
            first_table = self._get_rule_table(first_ref.rule) if first_ref else None
            first_rule = first_ref.rule if first_ref else None
            sigma_field = self._reverse_resolve_field(kql_field, first_table, first_rule) or kql_field
            mapped_names = [
                self._resolve_field_for_table(sigma_field, self._get_rule_table(rr.rule), rr.rule)
                for rr in rule.referenced_rules
            ]
            canonical = Counter(mapped_names).most_common(1)[0][0]
            my_mapped = self._resolve_field_for_table(sigma_field, table, base_rule)
            if my_mapped != canonical:
                extends.append(f"| extend {canonical} = {my_mapped}")
        return "\n".join(extends)

    def _get_timestamp_field(self) -> str:
        """Return the timestamp field name, preferring any value set by the active pipeline."""
        pipeline = getattr(self, "last_processing_pipeline", None)
        if pipeline is not None:
            return pipeline.state.get("timestamp_field", self.timestamp_field)
        return self.timestamp_field

    def _convert_correlation_value_rule(
        self,
        rule: SigmaCorrelationRule,
        aggregation_expressions: Dict[str, str],
        condition_expressions: Dict[str, str],
        output_format: Optional[str] = None,
        method: str = "default",
    ) -> list[str]:
        search = self.convert_correlation_search(rule, output_format=output_format)
        groupby = (", " + ", ".join(rule.group_by)) if rule.group_by else ""
        timespan = self._correlation_timespan_to_kql(rule.timespan)
        aggregate = aggregation_expressions[method].format(
            field=rule.condition.fieldref,
            timespan=timespan,
            groupby=groupby,
            timestamp=self._get_timestamp_field(),
        )
        op_map = {
            SigmaCorrelationConditionOperator.GT: ">",
            SigmaCorrelationConditionOperator.GTE: ">=",
            SigmaCorrelationConditionOperator.LT: "<",
            SigmaCorrelationConditionOperator.LTE: "<=",
            SigmaCorrelationConditionOperator.EQ: "==",
        }
        op = op_map[rule.condition.op]
        condition = condition_expressions[method].format(op=op, count=rule.condition.count)
        query = self.default_correlation_query[method].format(search=search, aggregate=aggregate, condition=condition)
        return [query]

    def convert_correlation_value_count_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        return self._convert_correlation_value_rule(
            rule, self.value_count_aggregation_expression, self.value_count_condition_expression, output_format, method
        )

    def convert_correlation_value_avg_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        return self._convert_correlation_value_rule(
            rule, self.value_avg_aggregation_expression, self.value_avg_condition_expression, output_format, method
        )

    def convert_correlation_value_median_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        return self._convert_correlation_value_rule(
            rule,
            self.value_median_aggregation_expression,
            self.value_median_condition_expression,
            output_format,
            method,
        )

    def convert_correlation_value_sum_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        return self._convert_correlation_value_rule(
            rule, self.value_sum_aggregation_expression, self.value_sum_condition_expression, output_format, method
        )

    def convert_correlation_value_percentile_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        if not hasattr(rule.condition, "percentile"):
            raise ValueError("Percentile value must be specified in condition for value_percentile correlation rules.")
        search = self.convert_correlation_search(rule, output_format=output_format)
        groupby = (", " + ", ".join(rule.group_by)) if rule.group_by else ""
        timespan = self._correlation_timespan_to_kql(rule.timespan)
        aggregate = self.value_percentile_aggregation_expression[method].format(
            field=rule.condition.fieldref,
            timespan=timespan,
            groupby=groupby,
            percentile=rule.condition.count,
            timestamp=self._get_timestamp_field(),
        )
        query = self.default_correlation_query[method].format(search=search, aggregate=aggregate, condition=None)
        return [query]

    def convert_correlation_event_count_rule(
        self, rule: SigmaCorrelationRule, output_format: Optional[str] = None, method: str = "default"
    ) -> list[str]:
        return self._convert_correlation_value_rule(
            rule, self.event_count_aggregation_expression, self.event_count_condition_expression, output_format, method
        )

    def _correlation_timespan_to_kql(self, timespan: object) -> str:
        """Convert SigmaCorrelationTimespan into valid KQL timespan literal."""
        spec = getattr(timespan, "spec", None)
        if isinstance(spec, str) and spec:
            return spec

        count = getattr(timespan, "count", None)
        unit = getattr(timespan, "unit", None)
        if isinstance(count, int) and count > 0 and isinstance(unit, str):
            mapped_unit = self.timespan_mapping.get(unit, unit)
            return f"{count}{mapped_unit}"

        return str(timespan)
