import string
from secrets import choice

from aws_cdk import (
    aws_ec2,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_s3 as s3,
    aws_rds as rds,
    aws_events as events,
    aws_events_targets as targets,
    RemovalPolicy,
    aws_secretsmanager as sm,
    aws_iam as iam,
    aws_kms as kms,
    aws_logs as logs,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    aws_certificatemanager as acm,
    Stack, CfnOutput, Duration, Token, Tags, aws_cloudfront
)
from aws_cdk.aws_elasticloadbalancingv2 import ApplicationLoadBalancer, ApplicationProtocol, HealthCheck, ListenerAction
from aws_cdk.aws_s3 import IBucket
from aws_cdk.aws_wafv2 import CfnWebACLAssociation
from aws_cdk.custom_resources import AwsCustomResource, AwsSdkCall, PhysicalResourceId, AwsCustomResourcePolicy
from cdk_nag import NagSuppressions
from constructs import Construct
from datetime import datetime, timezone

from galv_cdk.nag_suppressions import suppress_nags_pre_synth
from galv_cdk.utils import get_aws_custom_cert_instructions, inject_protected_env, create_waf_scope_web_acl


class GalvBackend(Stack):
    def __init__(self, scope: Construct, construct_id: str, log_bucket: IBucket, certificate_arn: str = None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.project_tag = self.node.try_get_context("projectNameTag") or "galv"
        self.name = self.node.try_get_context("name") or "galv"

        self.is_production = self.node.try_get_context("isProduction")
        if self.is_production is None:
            self.is_production = True

        self.removal_protection = self.node.try_get_context("removalProtection")
        if self.removal_protection is None:
            self.removal_protection = self.is_production

        self.domain_name = self.node.try_get_context("domainName")
        backend_subdomain = self.node.try_get_context("backendSubdomain") or "api"
        self.fqdn = f"{backend_subdomain}.{self.domain_name}".lstrip(".")

        frontend_subdomain = self.node.get_context("frontendSubdomain")
        self.frontend_fqdn = f"{frontend_subdomain}.{self.domain_name}".lstrip(".")

        self.is_route53_domain = self.node.try_get_context("isRoute53Domain")
        if self.is_route53_domain is None:
            self.is_route53_domain = True

        self.env_vars = self.node.try_get_context("backendEnvironment") or {}

        self.certificate_arn = certificate_arn
        self.secrets = {}

        self.stack = Stack.of(self)
        self.log_bucket = log_bucket

        self.log_retention = logs.RetentionDays.ONE_YEAR if self.removal_protection else logs.RetentionDays.ONE_DAY

        self.kms_key = kms.Key(self, f"{self.name}-KmsKey", enable_key_rotation=True)

        self.kms_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogsEncryption",
                actions=[
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                principals=[iam.ServicePrincipal("logs.amazonaws.com")],
                resources=["*"]
            )
        )

        self.backend_version = self.node.try_get_context("backendVersion") or "latest"
        if self.backend_version == "latest" and self.is_production:
            print("Using 'latest' backend version. This is not recommended for production deployments.")

        self._create_domain_certificates()
        self._update_log_bucket_access()
        self._create_vpc()

        self._create_security_groups()
        self._create_storage()
        self._create_cloudfront_distribution()
        self._create_database()
        self._create_loadbalancer()
        self._setup_environment()
        self._create_service()
        self._create_setup_task()
        self._create_validation_monitor_task()

        self._delayed_tasks()

        Tags.of(self).add("project-name", self.project_tag)

        suppress_nags_pre_synth(self)

    def _create_domain_certificates(self):
        # Create the CDK app with the loaded context
        if self.certificate_arn is None and not self.is_route53_domain:
            raise ValueError(get_aws_custom_cert_instructions(self.fqdn))

        if self.is_route53_domain:
            print(f"Creating new certificate for {self.fqdn}")
            zone = route53.HostedZone.from_lookup(self, f"{self.name}-BackendHostedZone", domain_name=self.domain_name)
            self.certificate = acm.Certificate(
                self,
                f"{self.name}-BackendCertificate",
                domain_name=self.fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )
        else:
            print(f"Using existing certificate: {self.certificate_arn}")
            self.certificate = acm.Certificate.from_certificate_arn(self, f"{self.name}-BackendCertificate",
                                                                    self.certificate_arn)
        Tags.of(self.certificate).add("project-name", self.project_tag)

    def _update_log_bucket_access(self):
        """
        Create an S3 Bucket for storing logs.
        Some logs are stored in the bucket, and some are sent to CloudWatch, because not all logs can be sent to S3.
        :return:
        """
        self.log_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:*"],
                effect=iam.Effect.DENY,
                principals=[iam.StarPrincipal()],
                resources=[
                    self.log_bucket.bucket_arn,
                    self.log_bucket.arn_for_objects("*")
                ],
                conditions={"Bool": {"aws:SecureTransport": "false"}}
            )
        )

        self.log_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowALBLogging",
                principals=[
                    iam.ServicePrincipal("logdelivery.elasticloadbalancing.amazonaws.com"),
                    iam.ServicePrincipal("delivery.logs.amazonaws.com")
                ],
                actions=["s3:PutObject"],
                resources=[self.log_bucket.arn_for_objects("AWSLogs/*")],
                conditions={
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            )
        )

    def _create_vpc(self):
        """
        Create a VPC with public, private, and isolated subnets.
        Public subnets are used for the ALB, private subnets are used for the backend services, and isolated subnets are used for the database.
        :return:
        """

        # ==== Shared VPC ====
        self.vpc = aws_ec2.Vpc(
            self,
            f"{self.name}-Vpc",
            max_azs=2,
            ip_addresses=aws_ec2.IpAddresses.cidr("10.0.0.0/16"),
            subnet_configuration=[
                aws_ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=aws_ec2.SubnetType.PUBLIC,
                    map_public_ip_on_launch=False,
                    cidr_mask=24  # Adjust CIDR mask as needed
                ),
                aws_ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS,
                ),
                aws_ec2.SubnetConfiguration(
                    name="isolated",
                    subnet_type=aws_ec2.SubnetType.PRIVATE_ISOLATED,
                )
            ],
            nat_gateways=0,  # Avoid NAT gateway charges
            flow_logs={
                "AllTraffic": aws_ec2.FlowLogOptions(
                    destination=aws_ec2.FlowLogDestination.to_s3(self.log_bucket)
                )
            },
            enable_dns_hostnames=True,
            enable_dns_support=True,
        )
        Tags.of(self.vpc).add("project-name", self.project_tag)

        for subnet in self.vpc.private_subnets:
            Tags.of(subnet).add("AZ", subnet.availability_zone)

        # Add interface endpoints for private access to AWS services
        self.vpc_endpoint_sg = aws_ec2.SecurityGroup(self, f"{self.name}-EndpointSG", vpc=self.vpc)
        self.vpc_endpoint_sg.add_ingress_rule(aws_ec2.Peer.ipv4(self.vpc.vpc_cidr_block), aws_ec2.Port.tcp(443), "HTTPS from VPC")

        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=aws_ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            security_groups=[self.vpc_endpoint_sg],
            subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

        self.vpc.add_interface_endpoint(
            "CloudWatchLogsEndpoint",
            service=aws_ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            security_groups=[self.vpc_endpoint_sg],
            private_dns_enabled=True,
            subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

        self.vpc.add_interface_endpoint(
            "EcrApiEndpoint",
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR,
            subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.vpc_endpoint_sg],
        )

        self.vpc.add_interface_endpoint(
            "EcrDockerEndpoint",
            service=aws_ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.vpc_endpoint_sg],
        )

        # Allow services to access STS for IAM role assumption
        self.vpc.add_interface_endpoint(
            "StsEndpoint",
            service=aws_ec2.InterfaceVpcEndpointAwsService.STS,
            private_dns_enabled=True,
            subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[self.vpc_endpoint_sg]
        )

        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=aws_ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS)],
        )

    def _create_security_groups(self):
        """
        Create security groups for the ALB, backend service, database, and endpoint.
        """
        self.alb_sg = aws_ec2.SecurityGroup(self, f"{self.name}-ALBSG", vpc=self.vpc)
        self.backend_sg = aws_ec2.SecurityGroup(self, f"{self.name}-BackendServiceSG", vpc=self.vpc)
        self.db_sg = aws_ec2.SecurityGroup(self, f"{self.name}-DBSG", vpc=self.vpc)
        self.setup_sg = aws_ec2.SecurityGroup(self, f"{self.name}-SetupTaskSG", vpc=self.vpc)
        self.monitor_sg = aws_ec2.SecurityGroup(self, f"{self.name}-ValidationMonitorSG", vpc=self.vpc)
        self.lambda_sg = aws_ec2.SecurityGroup(self, f"{self.name}-LambdaSG", vpc=self.vpc)

        self.alb_sg.add_ingress_rule(aws_ec2.Peer.any_ipv4(), aws_ec2.Port.tcp(80), "HTTP from internet")
        self.alb_sg.add_ingress_rule(aws_ec2.Peer.any_ipv4(), aws_ec2.Port.tcp(443), "HTTPS from internet")
        self.alb_sg.add_ingress_rule(aws_ec2.Peer.any_ipv6(), aws_ec2.Port.tcp(80), "HTTP from internet")
        self.alb_sg.add_ingress_rule(aws_ec2.Peer.any_ipv6(), aws_ec2.Port.tcp(443), "HTTPS from internet")
        self.backend_sg.add_ingress_rule(self.alb_sg, aws_ec2.Port.tcp(8000), "Traffic from ALB")
        self.db_sg.add_ingress_rule(self.backend_sg, aws_ec2.Port.tcp(5432), "Postgres from backend service")
        self.db_sg.add_ingress_rule(self.setup_sg, aws_ec2.Port.tcp(5432), "Postgres from setup task")
        self.db_sg.add_ingress_rule(self.monitor_sg, aws_ec2.Port.tcp(5432), "Postgres from monitor task")

        self.vpc_endpoint_sg.add_ingress_rule(
            aws_ec2.Peer.security_group_id(self.backend_sg.security_group_id),
            aws_ec2.Port.tcp(443),
            "Allow HTTPS from backend service to ECR endpoints"
        )
        self.vpc_endpoint_sg.add_ingress_rule(
            aws_ec2.Peer.security_group_id(self.monitor_sg.security_group_id),
            aws_ec2.Port.tcp(443),
            "Allow HTTPS from monitor task to ECR endpoints"
        )
        self.vpc_endpoint_sg.add_ingress_rule(
            aws_ec2.Peer.security_group_id(self.setup_sg.security_group_id),
            aws_ec2.Port.tcp(443),
            "Allow HTTPS from setup task to VPC endpoints"
        )

    def _create_storage(self):
        """
        Create an S3 bucket for backend storage. Used for media and data files.
        """
        self.media_bucket = s3.Bucket(
            self,
            f"{self.name}-BackendStorage",
            removal_policy=RemovalPolicy.RETAIN if self.removal_protection else RemovalPolicy.DESTROY,
            auto_delete_objects=not self.removal_protection,
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.kms_key,
            object_ownership=s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,  # Enables ACLs
            enforce_ssl=True,
            block_public_access=s3.BlockPublicAccess(
                block_public_acls=False,
                ignore_public_acls=False,
                block_public_policy=True,
                restrict_public_buckets=True
            ),  # Have to allow ACL to let Django write to the bucket
            server_access_logs_bucket=self.log_bucket,
            server_access_logs_prefix=f"{self.name}-BackendStorage-access-logs"
        )
        self.media_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:*"],
                effect=iam.Effect.DENY,
                principals=[iam.StarPrincipal()],
                resources=[
                    self.media_bucket.bucket_arn,
                    self.media_bucket.arn_for_objects("*")
                ],
                conditions={"Bool": {"aws:SecureTransport": "false"}}
            )
        )
        self.media_bucket.add_cors_rule(
            allowed_methods=[
                s3.HttpMethods.GET,
                s3.HttpMethods.HEAD,
            ],
            allowed_origins=[f"https://{self.fqdn}", f"https://{self.frontend_fqdn}"],  # or restrict to your domains
            allowed_headers=["*"],
            exposed_headers=["Content-Disposition", "Galv-Storage-Redirect-URL"],
            max_age=3000,
        )
        self.media_bucket.node.add_dependency(self.kms_key)

        self.static_assets_bucket = s3.Bucket(
            self,
            f"{self.name}-StaticAssetsBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
        )

    def _create_cloudfront_distribution(self):
        oac = aws_cloudfront.CfnOriginAccessControl(
            self,
            f"{self.name}-StaticOAC",
            origin_access_control_config=aws_cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name=f"{self.name}-StaticCDN-OAC",
                origin_access_control_origin_type="s3",
                signing_behavior="always",
                signing_protocol="sigv4",
                description="OAC for Django static files CDN",
            ),
        )

        self.static_assets_distribution = aws_cloudfront.CfnDistribution(
            self,
            f"{self.name}-StaticAssetsCDN",
            distribution_config=aws_cloudfront.CfnDistribution.DistributionConfigProperty(
                enabled=True,
                default_root_object="index.html",
                origins=[
                    aws_cloudfront.CfnDistribution.OriginProperty(
                        id=f"{self.name}-StaticAssetsOrigin",
                        domain_name=self.static_assets_bucket.bucket_regional_domain_name,
                        s3_origin_config=aws_cloudfront.CfnDistribution.S3OriginConfigProperty(
                            origin_access_identity=""
                        ),
                        origin_access_control_id=oac.ref,
                    )
                ],
                default_cache_behavior=aws_cloudfront.CfnDistribution.DefaultCacheBehaviorProperty(
                    target_origin_id=f"{self.name}-StaticAssetsOrigin",
                    viewer_protocol_policy="redirect-to-https",
                    allowed_methods=["GET", "HEAD"],
                    cached_methods=["GET", "HEAD"],
                    compress=True,
                    cache_policy_id=aws_cloudfront.CachePolicy.CACHING_OPTIMIZED.cache_policy_id,
                ),
                viewer_certificate=aws_cloudfront.CfnDistribution.ViewerCertificateProperty(
                    cloud_front_default_certificate=True,
                )
            ),
        )

        self.static_assets_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[self.static_assets_bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{self.account}:distribution/{self.static_assets_distribution.ref}"
                    }
                },
            )
        )

        CfnOutput(self, "StaticAssetsCDN", value=f"https://{self.static_assets_distribution.attr_domain_name}")

    def _create_database(self):
        """
        Create an RDS Postgres instance and a secret to store DB credentials.
        """
        self.db_secret = rds.DatabaseSecret(
            self,
            f"{self.name}-DbSecret",
            username="galvuser"
        )

        db_name = "galvdb"

        self.db_instance = rds.DatabaseInstance(
            self,
            f"{self.name}-BackendDatabase",
            engine=rds.DatabaseInstanceEngine.postgres(
                version=rds.PostgresEngineVersion.VER_16_3
            ),
            storage_encrypted=True,
            vpc=self.vpc,
            vpc_subnets=aws_ec2.SubnetSelection(subnet_group_name="isolated"),
            security_groups=[self.db_sg],
            instance_type=aws_ec2.InstanceType.of(
                aws_ec2.InstanceClass.BURSTABLE3, aws_ec2.InstanceSize.MICRO
            ),
            publicly_accessible=False,
            allocated_storage=20,
            removal_policy=RemovalPolicy.RETAIN if self.removal_protection else RemovalPolicy.DESTROY,
            deletion_protection=self.removal_protection,
            database_name=db_name,
            credentials=rds.Credentials.from_secret(self.db_secret),
        )

        if not self.removal_protection:
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
            "POSTGRES_DB": db_name,
            "POSTGRES_SSLMODE": "require",
        })

    def _create_loadbalancer(self):

        alb = ApplicationLoadBalancer(
            self,
            f"{self.name}-BackendALB",
            vpc=self.vpc,
            internet_facing=True,
            security_group=self.alb_sg,
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PUBLIC),
        )
        alb.log_access_logs(
            bucket=self.log_bucket,
            prefix=f"{self.name}-BackendALB-AccessLogs",
        )

        self.load_balancer = alb

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

        smtp_secret_name = self.node.try_get_context("smtpSecretName") or f"{self.name}-smtp"
        try:
            smtp_secret = sm.Secret.from_secret_name_v2(
                self, f"{self.name}-SmtpSecret", secret_name=smtp_secret_name
            )

            self.secrets.update({
                "DJANGO_EMAIL_HOST_USER": ecs.Secret.from_secrets_manager(smtp_secret, field="DJANGO_EMAIL_HOST_USER"),
                "DJANGO_EMAIL_HOST_PASSWORD": ecs.Secret.from_secrets_manager(smtp_secret, field="DJANGO_EMAIL_HOST_PASSWORD"),
            })
        except Exception as e:
            raise ValueError(
                f"SMTP credentials secret not found. Please create the secret named '{smtp_secret_name}' "
                f"with required keys DJANGO_EMAIL_HOST_USER and DJANGO_EMAIL_HOST_PASSWORD."
            ) from e

        inject_protected_env(self.env_vars, {
            "DJANGO_EMAIL_HOST": f"email-smtp.{self.stack.region}.amazonaws.com",
            "DJANGO_EMAIL_PORT": "587",
            "DJANGO_EMAIL_USE_TLS": "True",
            "DJANGO_EMAIL_USE_SSL": "False",
            "DJANGO_DEFAULT_FROM_EMAIL": sender_address,
            "DJANGO_AWS_S3_REGION_NAME": self.stack.region,
            "DJANGO_AWS_STORAGE_BUCKET_NAME": self.media_bucket.bucket_name,
            "DJANGO_STORE_MEDIA_FILES_ON_S3": "True",
            "DJANGO_STORE_STATIC_FILES_ON_S3": "True",
            "DJANGO_LABS_USE_OUR_S3_STORAGE": "True",
            "DJANGO_LAB_STORAGE_QUOTA_BYTES": str(5 * 1024 * 1024 * 1024),
            "DJANGO_SECRET_KEY": "".join([choice(string.ascii_letters + string.digits + string.punctuation.replace("\"", "").replace("\'", "").replace("\\", "")) for _ in range(50)]),
            "VIRTUAL_HOST": self.fqdn,
            "FRONTEND_VIRTUAL_HOST": f"https://{self.frontend_fqdn}",
            "PYTHONPATH": "/code/backend_django",
            "DJANGO_ELB_HOST": self.load_balancer.load_balancer_dns_name,
            "DJANGO_ALLOWED_CIDR_NETS": ",".join(subnet.ipv4_cidr_block for subnet in self.vpc.public_subnets),
            "SECURE_PROXY_SSL_HEADER": "HTTP_X_FORWARDED_PROTO:https",  # tell Django to trust the ALB's forwarded headers
            "AWS_DEFAULT_REGION": self.stack.region,
            "AWS_REGION": self.stack.region,
            "AWS_STS_REGIONAL_ENDPOINTS": "regional",  # use regional STS endpoints because our VPC endpoints are regional
            "DJANGO_STATIC_FILES_BUCKET_NAME": self.static_assets_bucket.bucket_name,
            "DJANGO_STATIC_FILES_CDN_DOMAIN": self.static_assets_distribution.attr_domain_name,
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
        web_log_group.node.add_dependency(self.kms_key)

        self.repo = ecr.Repository.from_repository_name(
            self,
            f"{self.name}-BackendRepo",
            repository_name="galv-backend"
        )

        enable_insights = self.node.try_get_context("enableContainerInsights")
        if enable_insights is None:
            enable_insights = self.is_production

        self.cluster = ecs.Cluster(
            self,
            f"{self.name}-Cluster",
            vpc=self.vpc,
            container_insights_v2=
            ecs.ContainerInsights.ENABLED if enable_insights else ecs.ContainerInsights.DISABLED,
        )
        Tags.of(self.cluster).add("project-name", self.project_tag)

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

        task_definition = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-BackendTaskDef",
            cpu=1024,
            memory_limit_mib=2048,
        )

        task_definition.add_container(
            f"{self.name}-BackendContainer",
            image=ecs.ContainerImage.from_ecr_repository(
                repository=self.repo,
                tag=self.backend_version
            ),
            command=["gunicorn --bind 0.0.0.0:8000 config.wsgi"],
            entry_point=["/bin/sh", "-c"],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=f"{self.name}-BackendService",
                log_group=web_log_group,
            ),
            environment={
                **self.env_vars,
                "ENVIRONMENT": self.name,
                "S3_BUCKET": self.media_bucket.bucket_name,
            },
            secrets=self.secrets if self.secrets else None,
            port_mappings=[
                ecs.PortMapping(
                    container_port=8000,
                    host_port=8000,
                )
            ],
        )

        self.service = ecs.FargateService(
            self,
            f"{self.name}-BackendService",
            cluster=self.cluster,
            task_definition=task_definition,
            desired_count=1,
            min_healthy_percent=100,
            max_healthy_percent=200,
            health_check_grace_period=Duration.seconds(60),
            security_groups=[self.backend_sg],
            vpc_subnets=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PUBLIC),
            circuit_breaker=ecs.DeploymentCircuitBreaker(
                rollback=True,
                enable=True
            ),
            enable_execute_command=not self.is_production,
            assign_public_ip=True,
        )

        listener = self.load_balancer.add_listener(
            f"{self.name}-BackendListener",
            port=443,
            certificates=[self.certificate],
            protocol=ApplicationProtocol.HTTPS,
            open=True
        )
        listener.add_targets(
            f"{self.name}-BackendTargetGroup",
            port=8000,
            targets=[self.service],
            health_check=HealthCheck(
                path="/health/",
                interval=Duration.seconds(5),
                timeout=Duration.seconds(2),
                healthy_threshold_count=2,
                unhealthy_threshold_count=3,
            ),
            deregistration_delay=Duration.seconds(10),
        )
        self.load_balancer.add_listener(
            f"{self.name}-BackendHttpListener",
            port=80,
            open=True,
            default_action=ListenerAction.redirect(
                host=self.fqdn,
                port="443",
                protocol="HTTPS",
                permanent=True,
            )
        )

        self.media_bucket.grant_read_write(task_definition.task_role)
        self.media_bucket.grant_put_acl(task_definition.task_role)

        self.db_instance.connections.allow_default_port_from(self.service)

        web_acl_backend = create_waf_scope_web_acl(self, f"{self.name}-BackendWebACL", name=f"{self.name}-Backend", scope_type="REGIONAL", log_bucket=self.log_bucket)
        CfnWebACLAssociation(
            self,
            f"{self.name}-BackendWebACLAssociation",
            resource_arn=self.load_balancer.load_balancer_arn,
            web_acl_arn=web_acl_backend.attr_arn
        )

        if self.node.try_get_context("isRoute53Domain"):
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=self.node.try_get_context('domainName'))

            route53.ARecord(
                self,
                f"{self.name}-BackendAliasRecord",
                zone=zone,
                record_name=self.fqdn,
                target=route53.RecordTarget.from_alias(route53_targets.LoadBalancerTarget(self.load_balancer)),
            )
        else:
            CfnOutput(self, "BackendCNAME", value=f"{self.fqdn} -> {self.load_balancer.load_balancer_dns_name}")

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
        log_group.node.add_dependency(self.kms_key)

        self.setup_task_def.add_container(
            f"{self.name}-SetupDbContainer",
            image=ecs.ContainerImage.from_ecr_repository(
                repository=self.repo,
                tag=self.backend_version
            ),
            command=[(
                "echo make; "
                "python3 manage.py makemigrations --no-input; "
                "echo migrate; "
                "python3 manage.py migrate --no-input;echo superuser; "
                "python3 manage.py create_superuser --no-input; "
                "echo fixtures; "
                "python3 manage.py loaddata galv/fixtures/*; "
                "echo static; "
                "python3 manage.py collectstatic --noinput"
            )],
            entry_point=["/bin/sh", "-c"],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="setup-db",
                log_group=log_group,
            ),
            environment=self.env_vars,
            secrets=self.secrets,
        )

        self.static_assets_bucket.grant_read_write(self.setup_task_def.task_role)
        self.static_assets_bucket.grant_put_acl(self.setup_task_def.task_role)

        self.setup_task_def.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["sts:GetCallerIdentity"],
                resources=["*"]
            )
        )

        self.db_instance.connections.allow_default_port_from(self.setup_sg)

        v = self.backend_version
        if v == "latest":
            v = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        run_task = AwsSdkCall(
            service="ECS",
            action="runTask",
            parameters={
                "cluster": self.cluster.cluster_name,
                "launchType": "FARGATE",
                "taskDefinition": self.setup_task_def.task_definition_arn,
                "networkConfiguration": {
                    "awsvpcConfiguration": {
                        "subnets": [subnet.subnet_id for subnet in self.vpc.select_subnets(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS).subnets],
                        "assignPublicIp": "DISABLED",
                        "securityGroups": [self.setup_sg.security_group_id]
                    }
                }
            },
            physical_resource_id=PhysicalResourceId.of(f"{self.name}-RunSetupTask-{v}"),
        )

        self.setup_task = AwsCustomResource(
            self,
            f"{self.name}-RunSetupTask",
            on_create=run_task,
            on_update=run_task,
            policy=AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["ecs:RunTask", "iam:PassRole"],
                    resources=[
                        self.setup_task_def.task_definition_arn,
                        f"arn:aws:ecs:{self.region}:{self.account}:cluster/{self.cluster.cluster_name}",
                        self.setup_task_def.task_role.role_arn,
                        self.setup_task_def.execution_role.role_arn,
                    ]
                )
            ]),
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
        log_group.node.add_dependency(self.kms_key)

        self.monitor_task_def.add_container(
            f"{self.name}-ValidationMonitorContainer",
            image=ecs.ContainerImage.from_ecr_repository(
                repository=self.repo,
                tag=self.backend_version
            ),
            entry_point=["/bin/sh", "-c"],
            command=["python3 manage.py validate_against_schemas"],
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix=f"{self.name}-ValidationMonitor",
                log_group=log_group,
            ),
            environment=self.env_vars,
            secrets=self.secrets
        )

        self.media_bucket.grant_read_write(self.monitor_task_def.task_role)

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
                        subnet_selection=aws_ec2.SubnetSelection(subnet_type=aws_ec2.SubnetType.PRIVATE_WITH_EGRESS),
                        security_groups=[self.monitor_sg]
                    )
                ]
            )

        CfnOutput(self, "ValidationMonitorTaskDefArn", value=self.monitor_task_def.task_definition_arn)

    def _delayed_tasks(self):
        # ... after self._create_service() and self.log_bucket have both been run
        region = Stack.of(self).region

        if not Token.is_unresolved(region):
            self.load_balancer.log_access_logs(
                bucket=self.log_bucket,
                prefix=f"{self.name}-BackendService-ALB-logs"
            )

        # Secure the ALB after its other settings are complete
        alb = self.load_balancer.node.default_child

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
            "LoadBalancerAttributes.1.Value", str(self.removal_protection).lower()
        )
