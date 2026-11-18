import pytest

from cfripper.config.config import Config
from cfripper.model.enums import RuleGranularity, RuleMode, RuleRisk
from cfripper.model.result import Failure
from cfripper.rules import FullWildcardPrincipalRule
from cfripper.rules.wildcard_principals import GenericWildcardPrincipalRule
from tests.utils import compare_lists_of_failures, get_cfmodel_from


@pytest.fixture()
def good_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/good_template.json").resolve()


@pytest.fixture()
def bad_template():
    return get_cfmodel_from("rules/GenericWildcardPrincipalRule/bad_template.json").resolve()


def test_no_failures_are_raised(good_template):
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(good_template)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_failures_are_raised(bad_template):
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(bad_template)

    assert not result.valid
    assert compare_lists_of_failures(
        result.failures,
        [
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow full wildcard `*`, or wildcard in account ID like `arn:aws:iam::*:12345` at `somewhatrestricted:*`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
            Failure(
                granularity=RuleGranularity.RESOURCE,
                reason="PolicyA should not allow full wildcard `*`, or wildcard in account ID like `arn:aws:iam::*:12345` at `arn:aws:iam::*:12345`",
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"PolicyA"},
                resource_types={"AWS::IAM::Policy"},
            ),
        ],
    )


def test_generic_wildcard_ignores_kms_keys_since_they_have_another_rule_for_them():
    rule = GenericWildcardPrincipalRule(Config(aws_account_id="123456789", aws_principals=["999999999"]))
    model = get_cfmodel_from("rules/CrossAccountTrustRule/kms_basic.yml").resolve(
        extra_params={"Principal": "arn:aws:iam::*:*"}
    )
    result = rule.invoke(model)
    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_suffixless_wildcard_account_in_role_trust_policy_is_flagged():
    # Regression for the incident: `arn:aws:iam::*` (no resource suffix) must hit the same rule family
    # as the already-detected suffixed form `arn:aws:iam::*:12345`.
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_suffixless_wildcard.json").resolve()
    rule = GenericWildcardPrincipalRule(None)
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
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RoleWithSuffixlessWildcardAccount"},
                resource_types={"AWS::IAM::Role"},
            )
        ],
    )


def test_unresolved_parameter_placeholders_in_role_trust_policy_are_flagged():
    # Regression for the incident: trust policies assembled via parameter concatenation slipped
    # through when the parameter had no default value. Both the pycfmodel `UNDEFINED_PARAM_*`
    # form (Ref/Join) and the leftover `${...}` form (Sub) are treated as wildcard suspects.
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_unresolved_placeholders.json").resolve()
    rule = GenericWildcardPrincipalRule(None)
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
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
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
                risk_value=RuleRisk.MEDIUM,
                rule="GenericWildcardPrincipalRule",
                rule_mode=RuleMode.BLOCKING,
                actions=None,
                resource_ids={"RoleWithSubPlaceholder"},
                resource_types={"AWS::IAM::Role"},
            ),
        ],
    )


def test_resolved_parameter_in_role_trust_policy_is_not_flagged():
    # When the parameter has a default value it resolves to a concrete principal and must not
    # be mistaken for an unresolved placeholder / wildcard.
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_resolved_parameter.json").resolve()
    rule = GenericWildcardPrincipalRule(None)
    result = rule.invoke(model)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])


def test_unresolved_placeholder_failures_respect_rule_filters(default_allow_all_config):
    # The historical filter/allowlist semantics must keep applying to the newly detected shapes.
    # Uses FullWildcardPrincipalRule as it is the registered rule that shares the implementation.
    model = get_cfmodel_from("rules/GenericWildcardPrincipalRule/iam_role_trust_unresolved_placeholders.json").resolve()
    rule = FullWildcardPrincipalRule(default_allow_all_config)
    result = rule.invoke(model)

    assert result.valid
    assert compare_lists_of_failures(result.failures, [])
