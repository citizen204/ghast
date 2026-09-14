from typing import List, Set

from ghast import model, taint
from ghast.findings import Finding
from ghast.rules import Context, run_all


def analyse(text: str, path: str = "test.yml") -> List[Finding]:
    workflow = model.parse_text(text, path)
    assert workflow.parse_error is None, workflow.parse_error
    engine = taint.analyse(workflow)
    ctx = Context(workflow=workflow, engine=engine)
    findings = run_all(ctx)
    assert not ctx.errors, ctx.errors
    return findings


def rule_ids(findings: List[Finding]) -> Set[str]:
    return {f.rule_id for f in findings}


def of_rule(findings: List[Finding], rule_id: str) -> List[Finding]:
    return [f for f in findings if f.rule_id == rule_id]
