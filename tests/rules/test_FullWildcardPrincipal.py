import pytest

from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import FullWildcardPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/FullWildcardPrincipalRule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/FullWildcardPrincipalRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                rule_mode=RuleMode.BLOCKING,
                rule="FullWildcardPrincipalRule",
                reason="PolicyA should not allow full wildcard `*`, or wildcard in account ID like `arn:aws:iam::*:12345` at `*`",
                granularity=RuleGranularity.RESOURCE,
                risk_value=RuleRisk.HIGH,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            )
        ],
    )


def test_rule_supports_filter_config(bad_template, default_allow_all_config):
    rule = FullWildcardPrincipalRule(default_allow_all_config)
    result = rule.invoke(bad_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_suffixless_wildcard_account_in_role_trust_policy_is_flagged():
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_suffixless_wildcard.json").resolve()
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(model)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=(
                    "RoleWithSuffixlessWildcardAccount should not allow full wildcard `*`, "
                    "or wildcard in account ID like `arn:aws:iam::*:12345` at `arn:aws:iam::*`"
                ),
                risk_value=RuleRisk.HIGH,
                rule="FullWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RoleWithSuffixlessWildcardAccount"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_unresolved_parameter_placeholders_in_role_trust_policy_are_flagged():
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_unresolved_placeholders.json").resolve()
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(model)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=(
                    "RoleWithJoinPlaceholder should not allow full wildcard `*`, "
                    "or wildcard in account ID like `arn:aws:iam::*:12345` at "
                    "`arn:aws:iam::UNDEFINED_PARAM_AccountId:root`"
                ),
                risk_value=RuleRisk.HIGH,
                rule="FullWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RoleWithJoinPlaceholder"},
                resource_types={"AWS::IAM::Role"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason=(
                    "RoleWithSubPlaceholder should not allow full wildcard `*`, "
                    "or wildcard in account ID like `arn:aws:iam::*:12345` at "
                    "`arn:aws:iam::${AccountId}:root`"
                ),
                risk_value=RuleRisk.HIGH,
                rule="FullWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RoleWithSubPlaceholder"},
                resource_types={"AWS::IAM::Role"},
            ),
        ],
    )


def test_resolved_parameter_in_role_trust_policy_is_not_flagged():
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_resolved_parameter.json").resolve()
    rule = FullWildcardPrincipalRule(None)
    result = rule.invoke(model)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
