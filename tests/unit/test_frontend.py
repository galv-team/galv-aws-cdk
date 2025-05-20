# Horrible Hack to support NVM
from aws_cdk.aws_s3 import Bucket
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
from constructs import IConstruct

import _nvm_hack
from frontend_stack import GalvFrontend
from nag_supressions import suppress_nags_post_synth
from log_bucket_stack import LogBucketStack

_nvm_hack.hack_nvm_path()
# /HH

import unittest
from aws_cdk import App, Aspects, Stack
from aws_cdk.assertions import Match, Template


class TestGalvFrontend(unittest.TestCase):
    def setUp(self):
        self.app = App(context={
            "name": "test",
            "mailFromUser": "test",
            "mailFromDomain": "example.com",
            "projectNameTag": "galv",
            "backendEnvironment": {
                "DJANGO_SUPERUSER_USERNAME": "admin",
                "DJANGO_LOG_LEVEL": "INFO",
                "DJANGO_USER_ACTIVATION_OVERRIDE_ADDRESSES": "",
                "DJANGO_USER_ACTIVATION_TOKEN_EXPIRY_S": ""
            },
            "frontendSecretsName": "galv-frontend-secrets-ABCDEF",
            "frontendSecretsKeys": [],
            "backendSecretsName": "galv-backend-secrets-ABCDEF",
            "backendSecretsKeys": [
                "DJANGO_SUPERUSER_PASSWORD",
                "DJANGO_SECRET_KEY"
            ],
            "frontendSubdomain": "",
            "backendSubdomain": "api",
            "domainName": "example.com",
            "isRoute53Domain": True,
            "enableContainerInsights": True,  # suppresses nag findings
        })
        Aspects.of(self.app).add(AwsSolutionsChecks(verbose=True))
        Aspects.of(self.app).add(HIPAASecurityChecks())

        self.stack = GalvFrontend(
            self.app,
            "TestStack",
            log_bucket=LogBucketStack(self.app, "TestRootStack", name="test", is_production=False).log_bucket,
            env={
                "account": "123456789012",
                "region": "eu-west-2"
            }
        )
        self.app.synth()
        suppress_nags_post_synth(self.stack, self.stack.name)

        self.template = Template.from_stack(self.stack)
        self.project_tag = self.app.node.try_get_context("projectNameTag") or "galv"

    def test_no_unsuppressed_nag_findings(self):
        """
        Test that there are no unsuppressed CDK Nag findings in the stack.
        If any are found, include suggestions on where to apply suppressions.
        """
        findings = []

        def collect_findings(scope: IConstruct):
            for child in scope.node.children:
                collect_findings(child)
                for entry in child.node.metadata:
                    path = child.node.path
                    if entry.type == "cdk_nag":
                        level = entry.data.get("level")
                        rule_id = entry.data.get("ruleId")
                        message = entry.data.get("info", "")
                        findings.append({
                            "path": path,
                            "rule_id": rule_id,
                            "level": level,
                            "message": message,
                            "suggestion": f"[post-synth] NagSuppressions.add_resource_suppressions({path}.node.default_child, [{{'id': '{rule_id}', 'reason': 'TODO'}}])"
                        })
                    elif entry.type in ["aws:cdk:warning", "aws:cdk:error"]:
                        message = entry.data
                        rule_id = None
                        if isinstance(message, str) and ":" in message:
                            # Extract rule ID prefix like 'AwsSolutions-CB4'
                            rule_id = message.split(":", 1)[0].strip()

                        target = f"{path}" if path.endswith("/Resource") else f"{path}.node.default_child"
                        suggestion = (
                            f"[pre-synth?] NagSuppressions.add_resource_suppressions({target}, ...), "
                            f"[{{'id': '{rule_id}', 'reason': 'TODO'}}])"
                            if rule_id else
                            f"# Review suppression placement for {path}"
                        )

                        findings.append({
                            "path": path,
                            "rule_id": rule_id or entry.type,
                            "level": "Error" if entry.type == "aws:cdk:error" else "Warning",
                            "message": message,
                            "suggestion": suggestion
                        })

        collect_findings(self.app)

        if findings:
            formatted = "\n\n".join(
                f"[{f['level']}] {f['path']}: {f['rule_id']} - {f['message']}→ Suggest: {f['suggestion']}"
                for f in findings
            )
            self.fail(f"{len(findings)} Unresolved CDK Nag findings:\n\n{formatted}")

    def test_alb_created(self):
        self.template.resource_count_is("AWS::ElasticLoadBalancingV2::LoadBalancer", 1)

    def test_ecs_service_exists(self):
        self.template.resource_count_is("AWS::ECS::Service", 1)

    def test_fargate_cluster_exists(self):
        self.template.resource_count_is("AWS::ECS::Cluster", 1)

    def test_certificate_created(self):
        self.template.has_resource_properties("AWS::CertificateManager::Certificate", {
            "DomainName": Match.string_like_regexp("example\\.com"),
            "ValidationMethod": "DNS"
        })

    def test_route53_record_created(self):
        self.template.resource_count_is("AWS::Route53::RecordSet", 1)

    def test_waf_attached(self):
        self.template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Scope": "REGIONAL",
            "Rules": Match.array_with([
                Match.object_like({
                    "Name": Match.string_like_regexp(".*CommonRuleSet.*")
                })
            ])
        })

    def test_log_group_created(self):
        self.template.resource_count_is("AWS::Logs::LogGroup", 1)

    def test_no_dangerous_wildcard_iam_policies(self):
        resources = self.template.to_json().get("Resources", {})
        allowed_wildcards = {
            "s3:GetObject*",
            "s3:GetBucket*",
            "s3:PutObject",
            "s3:List*",
            "s3:DeleteObject*",
            "s3:Abort*",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*"
        }

        violations = []

        for logical_id, res in resources.items():
            if res.get("Type") == "AWS::IAM::Policy":
                doc = res["Properties"].get("PolicyDocument", {})
                statements = doc.get("Statement", [])
                for stmt in statements:
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]

                    for action in actions:
                        if "*" in action:
                            # Deny s3:*, *, or anything not explicitly allowed
                            if action not in allowed_wildcards:
                                violations.append(f"{logical_id} uses disallowed action: {action}")

        if violations:
            self.fail("Disallowed wildcard IAM actions:\n" + "\n".join(violations))


if __name__ == "__main__":
    unittest.main()