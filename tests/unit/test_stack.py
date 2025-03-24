import unittest
from aws_cdk import App
from aws_cdk.assertions import Template, Match

from galv_cdk.galv_stack import GalvStack


class TestGalvStack(unittest.TestCase):
    def setUp(self):
        self.app = App(context={
            "name": "test",
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
            ]
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
        # Check that the RDS instance allows ingress from the ECS service security group
        self.template.has_resource_properties("AWS::EC2::SecurityGroupIngress", {
            "FromPort": 5432,
            "ToPort": 5432,
            "IpProtocol": "tcp",
            "Description": Match.string_like_regexp(".*allow connections.*"),
        })

    def test_rds_database_name_set(self):
        self.template.has_resource_properties("AWS::RDS::DBInstance", {
            "DBName": "galvdb"
        })


if __name__ == '__main__':
    unittest.main()
