from sigma.processing.pipeline import QueryPostprocessingItem
from sigma.processing.postprocessing import QueryPostprocessingTransformation
from sigma.rule import SigmaRule

from ..kusto_common.conditions import QueryTableSetCondition


class PrependQueryTablePostprocessingTransformation(QueryPostprocessingTransformation):
    def apply(self, rule: SigmaRule, query: str) -> str:  # type: ignore # noqa: F821
        table = self._pipeline.state["query_table"]
        if query.lstrip().startswith(table):
            return query
        return f"{table}\n| where {query}"


def create_prepend_query_table_item():
    """Factory function to create a new PrependQueryTablePostprocessingItem"""
    return QueryPostprocessingItem(
        identifier="kusto_prepend_query_table",
        transformation=PrependQueryTablePostprocessingTransformation(),
        rule_conditions=[
            QueryTableSetCondition(),
        ],
    )
