# Horrible Hack to support NVM
import _nvm_hack
_nvm_hack.hack_nvm_path()
# /HH

import unittest
from aws_cdk import App
from aws_cdk.assertions import Template, Match

from galv_cdk.galv_stack import GalvStack


class TestGalvStack(unittest.TestCase):
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
            "frontendSecretsName": "galv-frontend-secrets",
            "frontendSecretsKeys": [],
            "backendSecretsName": "galv-backend-secrets",
            "backendSecretsKeys": [
                "DJANGO_SUPERUSER_PASSWORD",
                "DJANGO_SECRET_KEY"
            ],
        })
        self.stack = GalvStack(self.app, "TestStack")
        self.template = Template.from_stack(self.stack)
        self.project_tag = self.app.node.try_get_context("projectNameTag") or "galv"

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

    def test_frontend_bucket_created(self):
        self.template.has_resource("AWS::S3::Bucket", {
            "Properties": {
                "WebsiteConfiguration": {
                    "IndexDocument": "index.html"
                }
            }
        })

    def test_backend_bucket_created(self):
        resources = self.template.find_resources("AWS::S3::Bucket")

        matching_backend_buckets = [
            res for res in resources.values()
            if "WebsiteConfiguration" not in res.get("Properties", {})
        ]

        self.assertEqual(len(matching_backend_buckets), 1, "Expected exactly one backend S3 bucket")

    def test_rds_postgres_instance_created(self):
        self.template.has_resource_properties("AWS::RDS::DBInstance", {
            "Engine": "postgres"
        })

    def test_django_backend_service_created(self):
        self.template.resource_count_is("AWS::ECS::Service", 1)

    def test_react_frontend_distribution_created(self):
        self.template.has_resource("AWS::CloudFront::Distribution", {})

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
            "mailFromDomain": "example.com"
        })
        stack = GalvStack(app, "TestStack")
        template = Template.from_stack(stack)

        # Should create an Events::Rule to run the task
        template.resource_count_is("AWS::Events::Rule", 1)

    def test_validation_monitor_not_scheduled_when_disabled(self):
        app = App(context={
            "name": "test",
            "monitorIntervalMinutes": 0,
            "mailFromDomain": "example.com"
        })
        stack = GalvStack(app, "TestStack")
        template = Template.from_stack(stack)

        # Should NOT create an Events::Rule
        template.resource_count_is("AWS::Events::Rule", 0)


if __name__ == '__main__':
    unittest.main()
