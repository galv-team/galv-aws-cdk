# Horrible Hack to support NVM
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks

import _nvm_hack
from frontend_stack import GalvFrontend
from nag_supressions import suppress_nags_post_synth

_nvm_hack.hack_nvm_path()
# /HH

import unittest
from aws_cdk import App, Aspects
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
            env={
                "account": "123456789012",
                "region": "eu-west-2"
            }
        )
        self.app.synth()
        suppress_nags_post_synth(self.stack, self.stack.name)

        self.template = Template.from_stack(self.stack)
        self.project_tag = self.app.node.try_get_context("projectNameTag") or "galv"

    def test_web_acl_is_cloudfront_scoped(self):
        self.template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Scope": "CLOUDFRONT"
        })

    def test_web_acl_uses_aws_common_rules(self):
        self.template.has_resource_properties("AWS::WAFv2::WebACL", {
            "Rules": Match.array_with([
                Match.object_like({
                    "Statement": {
                        "ManagedRuleGroupStatement": Match.object_like({
                            "Name": "AWSManagedRulesCommonRuleSet",
                            "VendorName": "AWS"
                        })
                    }
                })
            ])
        })

    def test_log_bucket_created_with_encryption_and_block(self):
        self.template.has_resource_properties("AWS::S3::Bucket", {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": Match.array_with([
                    Match.object_like({
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    })
                ])
            },
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        })

    def test_frontend_bucket_created(self):
        self.template.has_resource("AWS::S3::Bucket", {
            "Properties": {
                "WebsiteConfiguration": {
                    "IndexDocument": "index.html"
                }
            }
        })

    def test_react_frontend_distribution_created(self):
        self.template.has_resource("AWS::CloudFront::Distribution", {})

    def test_frontend_certificate_created(self):
        self.template.has_resource_properties("AWS::CertificateManager::Certificate", {
            "DomainName": Match.string_like_regexp("^example.com$"),
            "ValidationMethod": "DNS"
        })

    def test_cert_domains_and_cdn_aliases(self):
        template = Template.from_stack(self.stack)

        # Check CloudFront distribution uses expected alias
        template.has_resource_properties("AWS::CloudFront::Distribution", {
            "DistributionConfig": {
                "Aliases": Match.array_with(["example.com"])
            }
        })

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