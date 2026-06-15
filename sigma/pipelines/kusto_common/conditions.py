from dataclasses import dataclass
from typing import Union

from sigma.correlations import SigmaCorrelationRule
from sigma.processing.conditions import RuleProcessingCondition
from sigma.rule import SigmaRule


@dataclass
class QueryTableSetCondition(RuleProcessingCondition):
    def match(
        self,
        rule: Union[SigmaRule, SigmaCorrelationRule],
    ) -> bool:
        """Match condition on Sigma rule."""
        # Multi-rule correlation includes table names inside each sub-query, so skip top-level prepend
        if isinstance(rule, SigmaCorrelationRule) and len(rule.referenced_rules) > 1:
            return False
        return self._pipeline.state.get("query_table", None) is not None
