from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_s3 as s3,
    aws_rds as rds,
    RemovalPolicy,
    aws_secretsmanager as sm,
    Stack,
)
from constructs import Construct
import os


class GalvBackend(Construct):
    def __init__(self, scope: Construct, id: str, *, vpc: ec2.Vpc) -> None:
        super().__init__(scope, id)

        name = self.node.try_get_context("name") or "galv"
        backend_version = self.node.try_get_context("backendVersion") or "latest"
        env_vars = self.node.try_get_context("backendEnvironment") or {}

        is_production = self.node.try_get_context("isProduction")
        if is_production is None:
            is_production = True

        stack = Stack.of(self)

        secrets_name = self.node.try_get_context("backendSecretsName")
        secrets = {}
        if secrets_name:
            full_secret = sm.Secret.from_secret_attributes(
                self,
                "BackendSecrets",
                secret_complete_arn=f"arn:aws:secretsmanager:{stack.region}:{stack.account}:secret:{secrets_name}"
            )

            # We'll construct the ECS `secrets` dict from the JSON structure at deploy time
            # But we must define it statically at synth time
            keys = self.node.try_get_context("backendSecretsKeys") or []

            for key in keys:
                secrets[key] = ecs.Secret.from_secrets_manager(full_secret, field=key)

        removal_policy = RemovalPolicy.RETAIN if is_production else RemovalPolicy.DESTROY
        auto_delete = False if is_production else True

        bucket = s3.Bucket(
            self,
            f"{name}-BackendStorage",
            removal_policy=removal_policy,
            auto_delete_objects=auto_delete,
        )

        db_secret = rds.DatabaseSecret(
            self,
            f"{name}-DbSecret",
            username="galvuser"
        )

        db_instance = rds.DatabaseInstance(
            self,
            f"{name}-BackendDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_3
            ),
            vpc=vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            publicly_accessible=False,
            allocated_storage=20,
            removal_policy=removal_policy,
            deletion_protection=is_production,
            database_name="galvdb",
        )

        secrets.update({
            "POSTGRES_PASSWORD": ecs.Secret.from_secrets_manager(db_secret, field="password"),
            "POSTGRES_USER": ecs.Secret.from_secrets_manager(db_secret, field="username"),
        })

        env_vars.update({
            "POSTGRES_HOST": db_instance.db_instance_endpoint_address,
            "POSTGRES_PORT": db_instance.db_instance_endpoint_port,
            "POSTGRES_DB": "galvdb"
        })

        cluster = ecs.Cluster(self, f"{name}-Cluster", vpc=vpc)

        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            f"{name}-BackendService",
            cluster=cluster,
            cpu=512,
            memory_limit_mib=1024,
            desired_count=1,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_registry(
                    f"ghcr.io/galv-team/galv-backend:{backend_version}"
                ),
                container_port=8000,
                environment={
                    **env_vars,
                    "ENVIRONMENT": name,
                    "S3_BUCKET": bucket.bucket_name,
                },
                secrets=secrets if secrets else None,
            ),
            public_load_balancer=True,
            task_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
        )

        bucket.grant_read_write(service.task_definition.task_role)
        db_instance.connections.allow_default_port_from(service.service)
