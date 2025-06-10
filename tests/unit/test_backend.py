# Horrible Hack to support NVM
from aws_cdk.aws_s3 import Bucket

import _nvm_hack
from nag_suppressions import suppress_nags_post_synth
from log_bucket_stack import LogBucketStack

_nvm_hack.hack_nvm_path()
# /HH

import unittest
from aws_cdk import App, Aspects, assertions, Stack
from aws_cdk.assertions import Template, Match
from constructs import IConstruct
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks

from galv_cdk.backend_stack import GalvBackend


class TestGalvBackend(unittest.TestCase):
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

        self.stack = GalvBackend(
            self.app,
            "TestStack",
            log_bucket=LogBucketStack(self.app, "TestRootStack", name="test", is_production=False).log_bucket,
            env={"account": "123456789012", "region": "eu-west-2"}
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
                        if isinstance(message, str) and ": " in message:
                            # Extract rule ID prefix like 'AwsSolutions-CB4'
                            rule_id = message.split(": ", 1)[0].strip()

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


    def assert_env_var_present(self, var_name):
        self.template.has_resource_properties("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": Match.array_with([
                Match.object_like({
                    "Environment": Match.array_with([
                        Match.object_like({"Name": var_name})
                    ])
                })
            ])
        })

    def assert_secret_present(self, secret_name):
        self.template.has_resource_properties("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": Match.array_with([
                Match.object_like({
                    "Secrets": Match.array_with([
                        Match.object_like({"Name": secret_name})
                    ])
                })
            ])
        })

    def test_rds_postgres_instance_created(self):
        self.template.has_resource_properties("AWS::RDS::DBInstance", {
            "Engine": "postgres"
        })

    def test_django_backend_service_created(self):
        self.template.resource_count_is("AWS::ECS::Service", 1)

    def test_all_resources_tagged_with_project_name(self):
        resources = self.template.to_json().get("Resources", {})

        for logical_id, resource in resources.items():
            properties = resource.get("Properties", {})

            # Only test resources that actually support tags
            tags = properties.get("Tags")
            if tags is None:
                continue  # Skip untaggable resources like route associations

            project_tags = [
                tag for tag in tags
                if tag.get("Key") == "project-name" and tag.get("Value") == self.project_tag
            ]

            self.assertTrue(
                project_tags,
                f"Resource '{logical_id}' is missing a 'project-name' tag with value '{self.project_tag}'"
            )

    def test_backend_env_vars(self):
        self.template.has_resource_properties("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": Match.array_with([
                Match.object_like({
                    "Environment": Match.array_with([
                        Match.object_like({
                            "Name": "DJANGO_SUPERUSER_USERNAME",
                            "Value": "admin"
                        })
                    ])
                })
            ])
        })

    def test_backend_secrets(self):
        self.template.has_resource_properties("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": Match.array_with([
                Match.object_like({
                    "Secrets": Match.array_with([
                        Match.object_like({
                            "Name": "DJANGO_SUPERUSER_PASSWORD"
                        }),
                        Match.object_like({
                            "Name": "DJANGO_SECRET_KEY"
                        })
                    ])
                })
            ])
        })

    def test_database_env_vars_injected(self):
        for var in ["POSTGRES_DB", "POSTGRES_HOST", "POSTGRES_PORT"]:
            with self.subTest(var=var):
                self.assert_env_var_present(var)

    def test_database_secrets_injected(self):
        for secret in ["POSTGRES_USER", "POSTGRES_PASSWORD"]:
            with self.subTest(secret=secret):
                self.assert_secret_present(secret)

    def test_backend_can_connect_to_database(self):
        ingresses = self.template.find_resources("AWS::EC2::SecurityGroupIngress")

        db_ingress = [
            props for props in ingresses.values()
            if props["Properties"]["IpProtocol"] == "tcp"
        ]

        self.assertTrue(db_ingress, "No TCP ingress rule found from backend to RDS")

    def test_rds_database_name_set(self):
        self.template.has_resource_properties("AWS::RDS::DBInstance", {
            "DBName": "galvdb"
        })

    def test_s3_env_vars_injected(self):
        """
        Test that the expected environment variables are injected into the backend container
        """
        expected_vars = [
            "DJANGO_AWS_S3_REGION_NAME",
            "DJANGO_AWS_STORAGE_BUCKET_NAME",
            "DJANGO_STORE_MEDIA_FILES_ON_S3",
            "DJANGO_STORE_STATIC_FILES_ON_S3",
            "DJANGO_LABS_USE_OUR_S3_STORAGE",
            "DJANGO_LAB_STORAGE_QUOTA_BYTES"
        ]
        for var in expected_vars:
            with self.subTest(var=var):
                self.assert_env_var_present(var)

    def test_email_env_and_secrets_injected(self):
        env_vars = [
            "DJANGO_EMAIL_HOST",
            "DJANGO_EMAIL_PORT",
            "DJANGO_EMAIL_USE_TLS",
            "DJANGO_EMAIL_USE_SSL",
            "DJANGO_DEFAULT_FROM_EMAIL"
        ]

        secret_keys = [
            "DJANGO_EMAIL_HOST_USER",
            "DJANGO_EMAIL_HOST_PASSWORD"
        ]

        for var in env_vars:
            with self.subTest(env_var=var):
                self.assert_env_var_present(var)

        for key in secret_keys:
            with self.subTest(secret_key=key):
                self.assert_secret_present(key)

    def test_setup_task_definition_exists(self):
        self.template.has_resource_properties("AWS::ECS::TaskDefinition", {
            "ContainerDefinitions": Match.array_with([
                Match.object_like({
                    "Command": Match.array_with([
                        Match.string_like_regexp(".*collectstatic.*")
                    ])
                })
            ])
        })

    def test_validation_monitor_scheduled_when_enabled(self):
        app = App(context={
            "name": "test",
            "monitorIntervalMinutes": 5,
            "mailFromDomain": "example.com",
            "domainName": "example.com",
            "frontendSubdomain": "",
        })
        stack = GalvBackend(
            app,
            "TestStack",
            log_bucket=LogBucketStack(app, "TestRootStack", name="test", is_production=False).log_bucket,
            env={"account": "123456789012", "region": "eu-west-2"}
        )
        template = Template.from_stack(stack)

        # Should create an Events::Rule to run the task
        template.resource_count_is("AWS::Events::Rule", 1)

    def test_validation_monitor_not_scheduled_when_disabled(self):
        app = App(context={
            "name": "test",
            "monitorIntervalMinutes": 0,
            "mailFromDomain": "example.com",
            "domainName": "example.com",
            "frontendSubdomain": "",
        })
        stack = GalvBackend(
            app,
            "TestStack",
            log_bucket=LogBucketStack(app, "TestRootStack", name="test", is_production=False).log_bucket,
            env={"account": "123456789012", "region": "eu-west-2"}
        )
        template = Template.from_stack(stack)

        # Should NOT create an Events::Rule
        template.resource_count_is("AWS::Events::Rule", 0)

    def test_vpc_subnets_and_endpoints(self):
        # Check Secrets Manager endpoint
        self.template.has_resource_properties("AWS::EC2::VPCEndpoint", {
            "ServiceName": assertions.Match.string_like_regexp("com.amazonaws.eu-west-2.secretsmanager")
        })


        # Secrets Manager interface endpoint
        self.template.has_resource_properties("AWS::EC2::VPCEndpoint", {
            "ServiceName": assertions.Match.string_like_regexp("secretsmanager")
        })

        # Check CloudWatch Logs endpoint
        self.template.has_resource_properties("AWS::EC2::VPCEndpoint", {
            "ServiceName": assertions.Match.string_like_regexp("com.amazonaws.eu-west-2.logs")
        })

        # VPC flow logs to S3
        self.template.has_resource_properties("AWS::EC2::FlowLog", {
            "LogDestinationType": "s3"
        })

    def test_no_default_security_groups(self):
        """
        Test that no default security groups are created
        """
        # Get the default SG logical ID
        default_sg_logical_id = "DefaultSecurityGroup"

        # Ensure no resource explicitly references the default SG
        resources = self.template.to_json()["Resources"]
        for logical_id, resource in resources.items():
            props = resource.get("Properties", {})
            if "SecurityGroupIds" in props:
                sg_ids = props["SecurityGroupIds"]
                self.assertNotIn(
                    {"Ref": default_sg_logical_id},
                    sg_ids,
                    f"Resource {logical_id} uses the default security group"
                )

    def test_networked_resources_have_explicit_security_groups(self):
        """
        Ensure all network-connected resources explicitly declare security groups.
        """
        resources = self.template.to_json().get("Resources", {})
        missing_sg = []

        # Logical IDs of Lambda-backed custom resources that are exempt
        allowed_lambda_ids = {
            "BackendtestRunSetupTaskCustomResource",  # The Lambda used by AwsCustomResource to trigger Fargate setup
        }

        for logical_id, res in resources.items():
            rtype = res.get("Type")
            props = res.get("Properties", {})

            if rtype == "AWS::RDS::DBInstance":
                if not props.get("VPCSecurityGroups"):
                    missing_sg.append((logical_id, rtype, props.get("DBInstanceIdentifier", "<no name>")))

            elif rtype == "AWS::ECS::Service":
                net_config = props.get("NetworkConfiguration", {}).get("AwsvpcConfiguration", {})
                if not net_config.get("SecurityGroups"):
                    missing_sg.append((logical_id, rtype, props.get("ServiceName", "<no name>")))

            elif rtype == "AWS::Lambda::Function":
                if (
                        props.get("Handler") == "index.handler"
                        and props.get("Runtime", "").startswith("nodejs")
                        and props.get("FunctionName") is None
                        and "VpcConfig" not in props
                ):
                    # Likely CDK-injected Lambda for AwsCustomResource. Skip.
                    continue
                vpc_config = props.get("VpcConfig", {})
                if not vpc_config.get("SecurityGroupIds"):
                    missing_sg.append((logical_id, rtype, props.get("FunctionName", "<no name>")))

        if missing_sg:
            lines = "\n".join(
                f"{rtype} ({name}) [logical ID: {lid}] missing security group"
                for lid, rtype, name in missing_sg
            )
            self.fail(f"The following resources are missing explicit security groups:\n{lines}")

    def test_backend_certificate_created(self):
        self.template.has_resource_properties("AWS::CertificateManager::Certificate", {
            "DomainName": "api.example.com",
            "ValidationMethod": "DNS"
        })

    def test_setup_task_cr_has_passrole_permission(self):
        resources = self.template.to_json().get("Resources", {})

        # Find the logical ID of the setup task role
        task_role_logical_id = None
        for name, res in resources.items():
            if res["Type"] == "AWS::IAM::Role" and "SetupDbTaskDefTaskRole" in name:
                task_role_logical_id = name
                break

        self.assertIsNotNone(task_role_logical_id, "Could not find setup task IAM role")

        # Search for iam:PassRole on that exact logical ID via Fn::GetAtt
        found = False
        for res in resources.values():
            if res["Type"] != "AWS::IAM::Policy":
                continue
            statements = res.get("Properties", {}).get("PolicyDocument", {}).get("Statement", [])
            for stmt in statements:
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "iam:PassRole" not in actions:
                    continue

                resource_entries = stmt.get("Resource", [])
                if not isinstance(resource_entries, list):
                    resource_entries = [resource_entries]

                for r in resource_entries:
                    try:
                        if isinstance(r, dict) and r.get("Fn::GetAtt", [])[0] == task_role_logical_id:
                            found = True
                    except IndexError:
                        pass

        self.assertTrue(found, f"iam:PassRole not granted on setup task role ({task_role_logical_id})")

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


if __name__ == '__main__':
    unittest.main()
