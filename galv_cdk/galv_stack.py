from aws_cdk import Stack, Environment, Tags
from aws_cdk import aws_ec2 as ec2
from constructs import Construct

from galv_cdk.frontend import GalvFrontend
from galv_cdk.backend import GalvBackend


class GalvStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        project_tag = self.node.try_get_context("projectNameTag") or "galv"
        name = self.node.try_get_context("name") or "galv"
        is_production = self.node.try_get_context("isProduction")
        if is_production is None:
            is_production = True

        # ==== Shared VPC ====
        vpc = ec2.Vpc(
            self,
            f"{name}-Vpc",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                ),
            ],
        )

        # ==== Frontend Deployment ====
        GalvFrontend(self, "Frontend", vpc=vpc)

        # ==== Backend Deployment ====
        GalvBackend(self, "Backend", vpc=vpc)

        Tags.of(self).add("project-name", project_tag)
