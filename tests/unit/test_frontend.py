# Horrible Hack to support NVM
from aws_cdk.aws_s3 import Bucket
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
from constructs import IConstruct

import _nvm_hack
from frontend_stack import GalvFrontend
from nag_suppressions import suppress_nags_post_synth
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
            backend_fqdn="api.example.com",
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

    def test_all_networked_resources_use_same_vpc(self):
        template = self.template.to_json()
        resources = template["Resources"]

        # Step 1: Map each subnet to its VPC
        subnet_to_vpc = {}
        for logical_id, resource in resources.items():
            if resource["Type"] == "AWS::EC2::Subnet":
                props = resource.get("Properties", {})
                vpc_id = props.get("VpcId")
                if isinstance(vpc_id, dict) and "Ref" in vpc_id:
                    subnet_to_vpc[logical_id] = vpc_id["Ref"]

        # Step 2: Track VPCs used by ECS services, SGs, and VPCEs
        vpc_references = set()

        for resource in resources.values():
            props = resource.get("Properties", {})
            rtype = resource["Type"]

            if rtype == "AWS::EC2::VPCEndpoint" or rtype == "AWS::EC2::SecurityGroup":
                vpc_id = props.get("VpcId")
                if isinstance(vpc_id, dict) and "Ref" in vpc_id:
                    vpc_references.add(vpc_id["Ref"])

            elif rtype == "AWS::ECS::Service":
                subnet_config = props.get("NetworkConfiguration", {}).get("AwsvpcConfiguration", {})
                subnet_ids = subnet_config.get("Subnets", [])
                for subnet in subnet_ids:
                    if isinstance(subnet, dict) and "Ref" in subnet:
                        subnet_id = subnet["Ref"]
                        if subnet_id in subnet_to_vpc:
                            vpc_references.add(subnet_to_vpc[subnet_id])
                        else:
                            # fallback if subnet → VPC mapping was missing
                            vpc_references.add(subnet_id)

        self.assertEqual(
            len(vpc_references), 1,
            f"Expected all networked resources to use the same VPC, but found: {vpc_references}"
        )


if __name__ == "__main__":
    unittest.main()