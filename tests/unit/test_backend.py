# Horrible Hack to support NVM
import _nvm_hack
from nag_supressions import suppress_nags_post_synth

_nvm_hack.hack_nvm_path()
# /HH

import unittest
from aws_cdk import App, Aspects, assertions
from aws_cdk.assertions import Template, Match
from constructs import IConstruct
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks

from galv_cdk.galv_stack import GalvBackend


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

    def test_backend_and_log_buckets_exist_and_configured(self):
        resources = self.template.to_json().get("Resources", {})

        backend_buckets = [
            (name, res) for name, res in resources.items()
            if res["Type"] == "AWS::S3::Bucket"
               and "BackendStorage" in name
        ]
        log_buckets = [
            (name, res) for name, res in resources.items()
            if res["Type"] == "AWS::S3::Bucket"
               and "LogBucket" in name
        ]

        self.assertEqual(len(backend_buckets), 1, "Expected one backend bucket")
        self.assertEqual(len(log_buckets), 1, "Expected one log bucket")

        backend_bucket = backend_buckets[0][1]
        log_bucket = log_buckets[0][1]

        # Check backend bucket has KMS encryption
        encryption_config = backend_bucket["Properties"].get("BucketEncryption", {})
        self.assertIn("ServerSideEncryptionConfiguration", encryption_config)
        algo = encryption_config["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"]["SSEAlgorithm"]
        self.assertEqual(algo, "aws:kms")

        # Check logging is enabled
        logging = backend_bucket["Properties"].get("LoggingConfiguration", {})
        self.assertIn("DestinationBucketName", logging)
        self.assertIn("BackendStorage-access-logs/", logging.get("LogFilePrefix"))

        # Check public access block
        public_block = backend_bucket["Properties"].get("PublicAccessBlockConfiguration", {})
        for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"):
            self.assertTrue(public_block.get(key), f"{key} should be true on backend bucket")

        # Log bucket should also block public access
        log_public_block = log_bucket["Properties"].get("PublicAccessBlockConfiguration", {})
        for key in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"):
            self.assertTrue(log_public_block.get(key), f"{key} should be true on log bucket")


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
                    "Command": ["/code/setup_db.sh"]
                })
            ])
        })

    def test_validation_monitor_scheduled_when_enabled(self):
        app = App(context={
            "name": "test",
            "monitorIntervalMinutes": 5,
            "mailFromDomain": "example.com",
            "domainName": "example.com",
        })
        stack = GalvBackend(app, "TestStack", env={"account": "123456789012", "region": "eu-west-2"})
        template = Template.from_stack(stack)

        # Should create an Events::Rule to run the task
        template.resource_count_is("AWS::Events::Rule", 1)

    def test_validation_monitor_not_scheduled_when_disabled(self):
        app = App(context={
            "name": "test",
            "monitorIntervalMinutes": 0,
            "mailFromDomain": "example.com",
            "domainName": "example.com",
        })
        stack = GalvBackend(app, "TestStack", env={"account": "123456789012", "region": "eu-west-2"})
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

    def test_only_alb_in_public_subnet(self):
        """
        Ensure only the ALB is assigned to the public subnet.
        """
        resources = self.template.to_json().get("Resources", {})
        public_subnet_ids = set()
        violations = []

        # Gather all public subnet logical IDs
        for logical_id, res in resources.items():
            if res.get("Type") == "AWS::EC2::Subnet" and "public" in logical_id.lower():
                public_subnet_ids.add(logical_id)

        # Check each resource with Subnet/NetworkConfiguration
        for logical_id, res in resources.items():
            rtype = res.get("Type")
            props = res.get("Properties", {})

            # Check ALB placement
            if rtype == "AWS::ElasticLoadBalancingV2::LoadBalancer":
                subnet_ids = props.get("Subnets", [])
                for subnet in subnet_ids:
                    if isinstance(subnet, dict) and "Ref" in subnet:
                        subnet_id = subnet["Ref"]
                        if subnet_id not in public_subnet_ids:
                            violations.append((logical_id, "ALB uses a non-public subnet"))

            # Check everything else
            elif "Subnets" in props or "NetworkConfiguration" in props:
                subnet_refs = []

                if "Subnets" in props:
                    subnet_refs = props["Subnets"]
                elif "NetworkConfiguration" in props:
                    awsvpc = props["NetworkConfiguration"].get("AwsvpcConfiguration", {})
                    subnet_refs = awsvpc.get("Subnets", [])

                for subnet in subnet_refs:
                    if isinstance(subnet, dict) and "Ref" in subnet:
                        subnet_id = subnet["Ref"]
                        if subnet_id in public_subnet_ids:
                            violations.append((logical_id, f"{rtype} assigned to public subnet"))

        if violations:
            details = "\n".join(f"{lid}: {msg}" for lid, msg in violations)
            self.fail(f"The following resources are improperly assigned to public subnets:\n{details}")

    def test_backend_certificate_created(self):
        self.template.has_resource_properties("AWS::CertificateManager::Certificate", {
            "DomainName": "api.example.com",
            "ValidationMethod": "DNS"
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

if __name__ == '__main__':
    unittest.main()
