import json

from aws_cdk import (
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_s3 as s3,
    aws_rds as rds,
    aws_events as events,
    aws_events_targets as targets,
    RemovalPolicy,
    aws_secretsmanager as sm,
    aws_logs as logs,
    Stack, CfnOutput, Duration
)
from aws_cdk.custom_resources import AwsCustomResource, PhysicalResourceId, AwsCustomResourcePolicy, AwsSdkCall
from constructs import Construct

from utils import inject_protected_env


class GalvBackend(Construct):
    def __init__(self, scope: Construct, id: str, *, vpc: ec2.Vpc) -> None:
        """
        Construct for deploying the Galv backend stack, including ECS services,
        S3, RDS, and scheduled tasks.
        """
        super().__init__(scope, id)

        self.name = self.node.try_get_context("name") or "galv"
        self.backend_version = self.node.try_get_context("backendVersion") or "latest"
        self.env_vars = self.node.try_get_context("backendEnvironment") or {}
        self.is_production = self.node.try_get_context("isProduction")
        if self.is_production is None:
            self.is_production = True

        self.stack = Stack.of(self)
        self.vpc = vpc
        self.secrets = {}

        self._create_storage()
        self._create_database()
        self._setup_environment()
        self._create_cluster()
        self._create_service()
        self._create_setup_task()
        self._create_validation_monitor_task()
        self._create_check_status_task()

    def _create_storage(self):
        """
        Create an S3 bucket for backend storage. Used for media and data files.
        """
        self.bucket = s3.Bucket(
            self,
            f"{self.name}-BackendStorage",
            removal_policy=RemovalPolicy.RETAIN if self.is_production else RemovalPolicy.DESTROY,
            auto_delete_objects=not self.is_production,
        )

    def _create_database(self):
        """
        Create an RDS Postgres instance and a secret to store DB credentials.
        """
        self.db_secret = rds.DatabaseSecret(
            self,
            f"{self.name}-DbSecret",
            username="galvuser"
        )

        self.db_instance = rds.DatabaseInstance(
            self,
            f"{self.name}-BackendDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_15_3
            ),
            vpc=self.vpc,
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            publicly_accessible=False,
            allocated_storage=20,
            removal_policy=RemovalPolicy.RETAIN if self.is_production else RemovalPolicy.DESTROY,
            deletion_protection=self.is_production,
            database_name="galvdb",
        )

        self.secrets.update({
            "POSTGRES_PASSWORD": ecs.Secret.from_secrets_manager(self.db_secret, field="password"),
            "POSTGRES_USER": ecs.Secret.from_secrets_manager(self.db_secret, field="username"),
        })

        inject_protected_env(self.env_vars, {
            "POSTGRES_HOST": self.db_instance.db_instance_endpoint_address,
            "POSTGRES_PORT": self.db_instance.db_instance_endpoint_port,
            "POSTGRES_DB": "galvdb",
        })

    def _setup_environment(self):
        """
        Configure application secrets and environment variables including SMTP credentials
        and S3/Django settings. Prevents accidental overrides of reserved keys.
        """
        email_user = self.node.try_get_context("mailFromUser") or f"{self.name}-no-reply"
        email_domain = self.node.try_get_context("mailFromDomain")
        if not email_domain:
            raise ValueError("mailFromDomain must be set in the context")

        sender_address = f"{email_user}@{email_domain}"

        smtp_secret = sm.Secret(
            self,
            f"{self.name}-SmtpSecret",
            secret_name=f"{self.name}-smtp",
            generate_secret_string=sm.SecretStringGenerator(
                secret_string_template=json.dumps({
                    "DJANGO_EMAIL_HOST_USER": sender_address
                }),
                generate_string_key="DJANGO_EMAIL_HOST_PASSWORD",
                exclude_punctuation=True
            )
        )

        self.secrets.update({
            "DJANGO_EMAIL_HOST_USER": ecs.Secret.from_secrets_manager(smtp_secret, field="DJANGO_EMAIL_HOST_USER"),
            "DJANGO_EMAIL_HOST_PASSWORD": ecs.Secret.from_secrets_manager(smtp_secret, field="DJANGO_EMAIL_HOST_PASSWORD"),
        })

        inject_protected_env(self.env_vars, {
            "DJANGO_EMAIL_HOST": f"email-smtp.{self.stack.region}.amazonaws.com",
            "DJANGO_EMAIL_PORT": "587",
            "DJANGO_EMAIL_USE_TLS": "True",
            "DJANGO_EMAIL_USE_SSL": "False",
            "DJANGO_DEFAULT_FROM_EMAIL": sender_address,
            "DJANGO_AWS_S3_REGION_NAME": self.stack.region,
            "DJANGO_AWS_STORAGE_BUCKET_NAME": self.bucket.bucket_name,
            "DJANGO_STORE_MEDIA_FILES_ON_S3": "True",
            "DJANGO_STORE_STATIC_FILES_ON_S3": "True",
            "DJANGO_LABS_USE_OUR_S3_STORAGE": "True",
            "DJANGO_LAB_STORAGE_QUOTA_BYTES": str(5 * 1024 * 1024 * 1024)
        })

        secrets_name = self.node.try_get_context("backendSecretsName")
        if secrets_name:
            full_secret = sm.Secret.from_secret_attributes(
                self,
                "BackendSecrets",
                secret_complete_arn=f"arn:aws:secretsmanager:{self.stack.region}:{self.stack.account}:secret:{secrets_name}"
            )
            keys = self.node.try_get_context("backendSecretsKeys") or []
            for key in keys:
                self.secrets[key] = ecs.Secret.from_secrets_manager(full_secret, field=key)

    def _create_cluster(self):
        """
        Create the ECS cluster and backend service security group.
        Required for deploying all ECS-based tasks and services.
        """
        self.cluster = ecs.Cluster(self, f"{self.name}-Cluster", vpc=self.vpc)
        self.service_sg = ec2.SecurityGroup(self, f"{self.name}-BackendSG", vpc=self.vpc)

    def _create_service(self):
        """
        Deploy the main backend web service using ECS Fargate and Load Balancing.
        Handles all user HTTP requests and hosts the Django application.
        """
        self.service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            f"{self.name}-BackendService",
            cluster=self.cluster,
            cpu=512,
            memory_limit_mib=1024,
            desired_count=1,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_registry(
                    f"ghcr.io/galv-team/galv-backend:{self.backend_version}"
                ),
                container_port=8000,
                environment={
                    **self.env_vars,
                    "ENVIRONMENT": self.name,
                    "S3_BUCKET": self.bucket.bucket_name,
                },
                secrets=self.secrets if self.secrets else None,
                entry_point=["gunicorn"],
                command=["--bind", "0.0.0.0:8000", "config.wsgi"],
            ),
            public_load_balancer=True,
            task_subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.service_sg]
        )

        self.service.target_group.configure_health_check(
            path="/health/",
            port="traffic-port",  # or "8000" explicitly
            healthy_http_codes="200",
            interval=Duration.seconds(30),
            timeout=Duration.seconds(10),
            healthy_threshold_count=2,
            unhealthy_threshold_count=2,
        )

        self.bucket.grant_read_write(self.service.task_definition.task_role)
        self.db_instance.connections.allow_default_port_from(self.service.service)

    def _create_setup_task(self):
        """
        The service requires initialization to create the superuser,
        prepare the database with migrations, and load fixtures.
        This runs once when the CDK app is deployed.
        """
        self.setup_sg = ec2.SecurityGroup(self, f"{self.name}-SetupTaskSG", vpc=self.vpc)

        self.setup_task_def = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-SetupDbTaskDef",
            cpu=512,
            memory_limit_mib=1024
        )

        self.setup_task_def.add_container(
            f"{self.name}-SetupDbContainer",
            image=ecs.ContainerImage.from_registry(f"ghcr.io/galv-team/galv-backend:{self.backend_version}"),
            command=["/code/setup_db.sh"],
            logging=ecs.LogDrivers.aws_logs(stream_prefix="setup-db"),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.bucket.grant_read_write(self.setup_task_def.task_role)
        self.db_instance.connections.allow_default_port_from(self.setup_sg)

        AwsCustomResource(
            self,
            f"{self.name}-RunSetupTask",
            on_create=AwsSdkCall(
                service="ECS",
                action="runTask",
                parameters={
                    "cluster": self.cluster.cluster_name,
                    "launchType": "FARGATE",
                    "taskDefinition": self.setup_task_def.task_definition_arn,
                    "networkConfiguration": {
                        "awsvpcConfiguration": {
                            "subnets": [subnet.subnet_id for subnet in self.vpc.private_subnets],
                            "assignPublicIp": "DISABLED",
                            "securityGroups": [self.setup_sg.security_group_id]
                        }
                    }
                },
                physical_resource_id=PhysicalResourceId.of(f"{self.name}-RunSetupTask")
            ),
            policy=AwsCustomResourcePolicy.from_sdk_calls(
                resources=AwsCustomResourcePolicy.ANY_RESOURCE
            )
        ).node.add_dependency(self.setup_task_def)

        CfnOutput(self, "SetupTaskDefinitionArn", value=self.setup_task_def.task_definition_arn)
        CfnOutput(self, "ClusterName", value=self.cluster.cluster_name)
        CfnOutput(self, "VpcSubnets", value="private")

    def _create_validation_monitor_task(self):
        """
        Periodically run a task that polls the database for resources that need validation.
        Ensures automated validation is triggered without keeping a container alive.
        """
        self.monitor_sg = ec2.SecurityGroup(self, f"{self.name}-ValidationMonitorSG", vpc=self.vpc)

        monitor_interval = self.node.try_get_context("monitorIntervalMinutes")
        if monitor_interval is None:
            monitor_interval = 5
        else:
            monitor_interval = int(monitor_interval)

        self.monitor_task_def = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-ValidationMonitorTaskDef",
            cpu=256,
            memory_limit_mib=512
        )

        self.monitor_task_def.add_container(
            f"{self.name}-ValidationMonitorContainer",
            image=ecs.ContainerImage.from_registry(f"ghcr.io/galv-team/galv-backend:{self.backend_version}"),
            command=["python", "manage.py", "validation_monitor"],
            logging=ecs.LogDrivers.aws_logs(stream_prefix="validation-monitor"),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.bucket.grant_read_write(self.monitor_task_def.task_role)
        self.db_instance.connections.allow_default_port_from(self.monitor_sg)

        if monitor_interval > 0:
            events.Rule(
                self,
                f"{self.name}-ValidationMonitorSchedule",
                schedule=events.Schedule.rate(Duration.minutes(monitor_interval)),
                targets=[
                    targets.EcsTask(
                        cluster=self.cluster,
                        task_definition=self.monitor_task_def,
                        subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                        security_groups=[self.monitor_sg]
                    )
                ]
            )

        CfnOutput(self, "ValidationMonitorTaskDefArn", value=self.monitor_task_def.task_definition_arn)

    def _create_check_status_task(self):
        """
        Create a task that checks the status of the backend service.
        Can be run automatically or manually to verify the service is running.
        """
        self.check_sg = ec2.SecurityGroup(self, f"{self.name}-CheckStatusSG", vpc=self.vpc)

        self.check_status_task_def = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-CheckStatusTaskDef",
            cpu=256,
            memory_limit_mib=512
        )

        self.check_status_task_def.add_container(
            f"{self.name}-CheckStatusContainer",
            image=ecs.ContainerImage.from_registry(f"ghcr.io/galv-team/galv-backend:{self.backend_version}"),
            command=["python", "manage.py", "check_status"],
            logging=ecs.LogDrivers.aws_logs(stream_prefix="check-status"),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.bucket.grant_read_write(self.check_status_task_def.task_role)
        self.db_instance.connections.allow_default_port_from(self.check_sg)

        CfnOutput(self, "CheckStatusTaskDefinitionArn", value=self.check_status_task_def.task_definition_arn)

        AwsCustomResource(
            self,
            f"{self.name}-RunCheckStatusTask",
            on_create=AwsSdkCall(
                service="ECS",
                action="runTask",
                parameters={
                    "cluster": self.cluster.cluster_name,
                    "launchType": "FARGATE",
                    "taskDefinition": self.check_status_task_def.task_definition_arn,
                    "networkConfiguration": {
                        "awsvpcConfiguration": {
                            "subnets": [subnet.subnet_id for subnet in self.vpc.private_subnets],
                            "assignPublicIp": "DISABLED",
                            "securityGroups": [self.check_sg.security_group_id]
                        }
                    }
                },
                physical_resource_id=PhysicalResourceId.of(f"{self.name}-RunCheckStatusTask")
            ),
            policy=AwsCustomResourcePolicy.from_sdk_calls(
                resources=AwsCustomResourcePolicy.ANY_RESOURCE
            )
        ).node.add_dependency(self.check_status_task_def)
