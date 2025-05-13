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
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as logs,
    aws_elasticloadbalancingv2 as elbv2,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    Stack, CfnOutput, Duration, Token
)
from aws_cdk.aws_certificatemanager import ICertificate, Certificate
from aws_cdk.custom_resources import AwsCustomResource, PhysicalResourceId, AwsCustomResourcePolicy, AwsSdkCall
from cdk_nag import NagSuppressions
from constructs import Construct

from utils import inject_protected_env, create_waf_scope_web_acl


class GalvBackend(Construct):
    def __init__(self, scope: Construct, id: str, *, vpc: ec2.Vpc, log_bucket: s3.Bucket|s3.IBucket, kms_key: kms.Key|kms.IKey, fqdn: str, backend_cert: ICertificate|Certificate) -> None:
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
        self.log_bucket = log_bucket
        self.kms_key = kms_key
        self.fqdn = fqdn
        self.backend_cert = backend_cert
        self.secrets = {}

        self.log_retention = logs.RetentionDays.ONE_YEAR if self.is_production else logs.RetentionDays.ONE_DAY

        self._create_security_groups()
        self._create_storage()
        self._create_database()
        self._setup_environment()
        self._create_cluster()
        self._create_service()
        self._create_setup_task()
        self._create_validation_monitor_task()

        self._delayed_tasks()

    def _create_security_groups(self):
        """
        Create security groups for the ALB, backend service, database, and endpoint.
        """
        self.alb_sg = ec2.SecurityGroup(self, f"{self.name}-ALBSG", vpc=self.vpc)
        self.backend_sg = ec2.SecurityGroup(self, f"{self.name}-BackendServiceSG", vpc=self.vpc)
        self.db_sg = ec2.SecurityGroup(self, f"{self.name}-DBSG", vpc=self.vpc)
        self.setup_sg = ec2.SecurityGroup(self, f"{self.name}-SetupTaskSG", vpc=self.vpc)
        self.monitor_sg = ec2.SecurityGroup(self, f"{self.name}-ValidationMonitorSG", vpc=self.vpc)
        self.lambda_sg = ec2.SecurityGroup(self, f"{self.name}-LambdaSG", vpc=self.vpc)

        self.alb_sg.add_ingress_rule(ec2.Peer.any_ipv4(), ec2.Port.tcp(443), "HTTPS from internet")
        self.backend_sg.add_ingress_rule(self.alb_sg, ec2.Port.tcp(8000), "Traffic from ALB")
        self.db_sg.add_ingress_rule(self.backend_sg, ec2.Port.tcp(5432), "Postgres from backend service")
        self.db_sg.add_ingress_rule(self.setup_sg, ec2.Port.tcp(5432), "Postgres from setup task")
        self.db_sg.add_ingress_rule(self.monitor_sg, ec2.Port.tcp(5432), "Postgres from monitor task")

    def _create_storage(self):
        """
        Create an S3 bucket for backend storage. Used for media and data files.
        """
        self.bucket = s3.Bucket(
            self,
            f"{self.name}-BackendStorage",
            removal_policy=RemovalPolicy.RETAIN if self.is_production else RemovalPolicy.DESTROY,
            auto_delete_objects=not self.is_production,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=self.log_bucket,
            server_access_logs_prefix=f"{self.name}-BackendStorage-access-logs/"
        )
        self.bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:*"],
                effect=iam.Effect.DENY,
                principals=[iam.StarPrincipal()],
                resources=[
                    self.bucket.bucket_arn,
                    self.bucket.arn_for_objects("*")
                ],
                conditions={"Bool": {"aws:SecureTransport": "false"}}
            )
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
                version=rds.PostgresEngineVersion.VER_16_3
            ),
            storage_encrypted=True,
            vpc=self.vpc,
            vpc_subnets=ec2.SubnetSelection(subnet_group_name="isolated"),
            security_groups=[self.db_sg],
            instance_type=ec2.InstanceType.of(
                ec2.InstanceClass.BURSTABLE3, ec2.InstanceSize.MICRO
            ),
            publicly_accessible=False,
            allocated_storage=20,
            removal_policy=RemovalPolicy.RETAIN if self.is_production else RemovalPolicy.DESTROY,
            deletion_protection=self.is_production,
            database_name="galvdb",
        )

        if not self.is_production:
            NagSuppressions.add_resource_suppressions(
                self.db_instance.node.default_child,
                [
                    {
                        "id": "AwsSolutions-RDS10",
                        "reason": "Deletion protection is disabled in non-production environments for cost and flexibility."
                    },
                    {
                        "id": "HIPAA.Security-RDSInstanceDeletionProtectionEnabled",
                        "reason": "RDS deletion protection is not required outside production."
                    }
                ]
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
            full_secret = sm.Secret.from_secret_name_v2(
                self,
                "BackendSecrets",
                secret_name=secrets_name
            )
            keys = self.node.try_get_context("backendSecretsKeys") or []
            for key in keys:
                self.secrets[key] = ecs.Secret.from_secrets_manager(full_secret, field=key)

    def _create_cluster(self):
        """
        Create the ECS cluster and backend service security group.
        Required for deploying all ECS-based tasks and services.
        """
        enable_insights = self.node.try_get_context("enableContainerInsights")
        if enable_insights is None:
            enable_insights = self.is_production

        self.cluster = ecs.Cluster(
            self,
            f"{self.name}-Cluster",
            vpc=self.vpc,
            container_insights_v2=
            ecs.ContainerInsights.ENABLED if enable_insights else ecs.ContainerInsights.DISABLED
        )

        if not enable_insights:
            NagSuppressions.add_resource_suppressions(
                self.cluster.node.default_child,
                [
                    {
                        "id": "AwsSolutions-ECS4",
                        "reason": "Container insights are disabled in dev to reduce CloudWatch costs."
                    }
                ]
            )

    def _create_service(self):
        """
        Deploy the main backend web service using ECS Fargate and Load Balancing.
        Handles all user HTTP requests and hosts the Django application.
        """
        web_log_group = logs.LogGroup(
            self,
            f"{self.name}-BackendWebLogGroup",
            retention=self.log_retention,
            encryption_key=self.kms_key
        )

        self.service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            f"{self.name}-BackendService",
            cluster=self.cluster,
            cpu=512,
            memory_limit_mib=1024,
            desired_count=1,
            min_healthy_percent=100,
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
                log_driver=ecs.LogDrivers.aws_logs(
                    stream_prefix=f"{self.name}-BackendService",
                    log_group=web_log_group
                )
            ),
            public_load_balancer=True,
            security_groups=[self.alb_sg],
            task_subnets=ec2.SubnetSelection(subnet_group_name="private"),
            certificate=self.backend_cert,
            protocol=elbv2.ApplicationProtocol.HTTPS,
        )

        self.bucket.grant_read_write(self.service.task_definition.task_role)

        self.db_instance.connections.allow_default_port_from(self.service.service)
        self.service.load_balancer.connections.allow_from_any_ipv4(ec2.Port.tcp(443))

        web_acl_backend = create_waf_scope_web_acl(self, f"{self.name}-BackendWebACL", name=self.name, scope_type="REGIONAL", log_bucket=self.log_bucket)
        cfn_alb = self.service.load_balancer.node.default_child
        cfn_alb.web_acl_id = web_acl_backend.ref

        if self.node.try_get_context("isRoute53Domain"):
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=self.node.try_get_context('domainName'))

            route53.ARecord(
                self,
                f"{self.name}-BackendAliasRecord",
                zone=zone,
                record_name=self.fqdn,
                target=route53.RecordTarget.from_alias(route53_targets.LoadBalancerTarget(self.service.load_balancer)),
            )
        else:
            CfnOutput(self, "BackendCNAME", value=f"{self.fqdn} -> {self.service.load_balancer.load_balancer_dns_name}")

    def _create_setup_task(self):
        """
        The service requires initialization to create the superuser,
        prepare the database with migrations, and load fixtures.
        This runs once when the CDK app is deployed.
        """
        self.setup_task_def = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-SetupDbTaskDef",
            cpu=512,
            memory_limit_mib=1024
        )

        log_group = logs.LogGroup(
            self,
            f"{self.name}-SetupDbLogGroup",
            retention=self.log_retention,
            encryption_key=self.kms_key
        )

        self.setup_task_def.add_container(
            f"{self.name}-SetupDbContainer",
            image=ecs.ContainerImage.from_registry(f"ghcr.io/galv-team/galv-backend:{self.backend_version}"),
            command=["/code/setup_db.sh"],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="setup-db",
                log_group=log_group,
            ),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.bucket.grant_read_write(self.setup_task_def.task_role)

        self.db_instance.connections.allow_default_port_from(self.setup_sg)

        self.setup_task = AwsCustomResource(
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
                            "subnets": [subnet.subnet_id for subnet in self.vpc.select_subnets(subnet_group_name="private").subnets],
                            "assignPublicIp": "DISABLED",
                            "securityGroups": [self.setup_sg.security_group_id]
                        }
                    }
                },
                physical_resource_id=PhysicalResourceId.of(f"{self.name}-RunSetupTask")
            ),
            policy=AwsCustomResourcePolicy.from_sdk_calls(
                resources=AwsCustomResourcePolicy.ANY_RESOURCE
            ),
            install_latest_aws_sdk=False,
        )

        self.setup_task.node.add_dependency(self.setup_task_def)

        CfnOutput(self, "SetupTaskDefinitionArn", value=self.setup_task_def.task_definition_arn)
        CfnOutput(self, "ClusterName", value=self.cluster.cluster_name)
        CfnOutput(self, "VpcSubnets", value="private")

    def _create_validation_monitor_task(self):
        """
        Periodically run a task that polls the database for resources that need validation.
        Ensures automated validation is triggered without keeping a container alive.
        """
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

        log_group = logs.LogGroup(
            self,
            f"{self.name}-ValidationMonitorLogGroup",
            retention=self.log_retention,
            encryption_key=self.kms_key
        )

        self.monitor_task_def.add_container(
            f"{self.name}-ValidationMonitorContainer",
            image=ecs.ContainerImage.from_registry(f"ghcr.io/galv-team/galv-backend:{self.backend_version}"),
            command=["python", "manage.py", "validation_monitor"],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=f"{self.name}-ValidationMonitor",
                log_group=log_group,
            ),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.bucket.grant_read_write(self.monitor_task_def.task_role)

        self.db_instance.connections.allow_default_port_from(self.monitor_sg)

        if monitor_interval > 0:
            rule = events.Rule(
                self,
                f"{self.name}-ValidationMonitorSchedule",
                schedule=events.Schedule.rate(Duration.minutes(monitor_interval)),
                targets=[
                    targets.EcsTask(
                        cluster=self.cluster,
                        task_definition=self.monitor_task_def,
                        subnet_selection=ec2.SubnetSelection(subnet_group_name="private"),
                        security_groups=[self.monitor_sg]
                    )
                ]
            )

        CfnOutput(self, "ValidationMonitorTaskDefArn", value=self.monitor_task_def.task_definition_arn)

    def _delayed_tasks(self):
        # ... after self._create_service() and self.log_bucket have both been run
        region = Stack.of(self).region

        if not Token.is_unresolved(region):
            self.service.load_balancer.log_access_logs(
                bucket=self.log_bucket,
                prefix=f"{self.name}-BackendService-ALB-logs/"
            )


        # Secure the ALB after its other settings are complete
        alb = self.service.load_balancer.node.default_child

        alb.add_property_override(
            "LoadBalancerAttributes.0.Key", "routing.http.drop_invalid_header_fields.enabled"
        )
        alb.add_property_override(
            "LoadBalancerAttributes.0.Value", "true"
        )
        alb.add_property_override(
            "LoadBalancerAttributes.1.Key", "deletion_protection.enabled"
        )
        alb.add_property_override(
            "LoadBalancerAttributes.1.Value", str(self.is_production).lower()
        )
