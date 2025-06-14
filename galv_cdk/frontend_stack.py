from aws_cdk import (
    Stack, CfnOutput,
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_route53_targets as route53_targets,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_logs as logs,
    aws_iam as iam,
    aws_s3 as s3, RemovalPolicy, Duration, Tags,
)
from aws_cdk.aws_elasticloadbalancingv2 import ApplicationLoadBalancer, ApplicationProtocol, HealthCheck, ListenerAction
from aws_cdk.aws_wafv2 import CfnWebACLAssociation
from cdk_nag import NagSuppressions
from constructs import Construct
from galv_cdk.nag_suppressions import suppress_nags_pre_synth
from galv_cdk.utils import get_aws_custom_cert_instructions, create_waf_scope_web_acl


class GalvFrontend(Stack):
    def __init__(
            self,
            scope: Construct,
            id: str,
            log_bucket: s3.IBucket,
            certificate_arn: str = None,
            backend_fqdn: str = None,
            **kwargs
    ) -> None:
        super().__init__(scope, id, **kwargs)

        self.name = self.node.try_get_context("name") or "galv"
        self.project_tag = self.node.try_get_context("projectNameTag") or "galv"

        self.is_production = self.node.try_get_context("isProduction")
        if self.is_production is None:
            self.is_production = True

        self.removal_protection = self.node.try_get_context("removalProtection")
        if self.removal_protection is None:
            self.removal_protection = self.is_production

        self.domain_name = self.node.get_context("domainName")
        self.subdomain = self.node.get_context("frontendSubdomain")
        self.fqdn = f"{self.subdomain}.{self.domain_name}".lstrip(".")
        self.backend_fqdn = backend_fqdn
        if not self.backend_fqdn:
            raise ValueError("backend_fqdn must be provided to GalvFrontend")
        self.is_route53_domain = self.node.try_get_context("isRoute53Domain")
        if self.is_route53_domain is None:
            self.is_route53_domain = True
        self.frontend_version = self.node.try_get_context("frontendVersion") or "latest"
        if self.frontend_version == "latest" and self.is_production:
            print("Using 'latest' frontend version. This is not recommended for production deployments.")

        self.log_bucket = log_bucket

        self._update_log_bucket_access()
        self._create_cert(certificate_arn)
        self._create_service()

        suppress_nags_pre_synth(self)

        Tags.of(self).add("project-name", self.project_tag)

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

    def _create_cert(self, certificate_arn: str):
        if certificate_arn is None and not self.is_route53_domain:
            raise ValueError(get_aws_custom_cert_instructions(self.fqdn))

        if self.is_route53_domain:
            print(f"Creating new certificate for {self.fqdn}")
            zone = route53.HostedZone.from_lookup(self, f"{self.name}-FrontendZone", domain_name=self.domain_name)
            self.certificate = acm.Certificate(
                self,
                f"{self.name}-FrontendCertificate",
                domain_name=self.fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )
            Tags.of(self.certificate).add("project-name", self.project_tag)
        else:
            print(f"Using existing certificate: {certificate_arn}")
            self.certificate = acm.Certificate.from_certificate_arn(
                self, f"{self.name}-FrontendCertificate", certificate_arn
            )

    def _create_service(self):
        vpc = ec2.Vpc(
            self,
            f"{self.name}-FrontendVpc",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24,
                ),
            ]
        )
        Tags.of(vpc).add("project-name", self.project_tag)
        alb_sg = ec2.SecurityGroup(
            self,
            f"{self.name}-FrontendALBSecurityGroup",
            vpc=vpc,
            allow_all_outbound=True,
            description="Security group for ALB (allow HTTP/S from anywhere)",
        )
        ecs_sg = ec2.SecurityGroup(
            self,
            f"{self.name}-FrontendECSSecurityGroup",
            vpc=vpc,
            allow_all_outbound=True,
            description="Security group for ECS (allow traffic from ALB)",
        )
        alb_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP traffic from anywhere",
        )
        alb_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS traffic from anywhere",
        )
        alb_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv6(),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP traffic from anywhere",
        )
        alb_sg.add_ingress_rule(
            peer=ec2.Peer.any_ipv6(),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS traffic from anywhere",
        )
        ecs_sg.add_ingress_rule(
            peer=alb_sg,
            connection=ec2.Port.tcp(80),
            description="Allow HTTP traffic from ALB",
        )

        vpc.add_interface_endpoint(
            "EcrApiEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[ecs_sg],
        )

        vpc.add_interface_endpoint(
            "EcrDockerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            security_groups=[ecs_sg],
        )

        enable_insights = self.node.try_get_context("enableContainerInsights")
        if enable_insights is None:
            enable_insights = self.is_production

        cluster = ecs.Cluster(
            self,
            f"{self.name}-FrontendCluster",
            vpc=vpc,
            container_insights_v2=
            ecs.ContainerInsights.ENABLED if enable_insights else ecs.ContainerInsights.DISABLED,
        )
        Tags.of(cluster).add("project-name", self.project_tag)

        if not enable_insights:
            NagSuppressions.add_resource_suppressions(
                cluster.node.default_child,
                [
                    {
                        "id": "AwsSolutions-ECS4",
                        "reason": "Container insights are disabled in dev to reduce CloudWatch costs."
                    }
                ]
            )

        repo = ecr.Repository.from_repository_name(
            self,
            f"{self.name}-FrontendRepo",
            repository_name="galv-frontend"
        )

        task_definition = ecs.FargateTaskDefinition(
            self,
            f"{self.name}-FrontendTaskDef",
            cpu=256,
            memory_limit_mib=512,
        )

        task_definition.add_container(
            f"{self.name}-FrontendContainer",
            image=ecs.ContainerImage.from_ecr_repository(
                repository=repo,
                tag=self.frontend_version
            ),
            logging=ecs.LogDrivers.aws_logs(
                stream_prefix="frontend",
                log_group=logs.LogGroup(
                    self,
                    f"{self.name}-FrontendLogGroup",
                    retention=logs.RetentionDays.ONE_YEAR if self.removal_protection else logs.RetentionDays.ONE_DAY,
                    removal_policy=RemovalPolicy.RETAIN if self.removal_protection else RemovalPolicy.DESTROY,
                ),
            ),
            port_mappings=[ecs.PortMapping(container_port=80)],
            environment={
                "ENV": "production" if self.is_production else "development",
                "LOG_LEVEL": "info",
                "VITE_GALV_API_BASE_URL": f"https://{self.backend_fqdn}",
                "VITE_GALV_ANALYTICS_URL": "https://plausible-oxrse.fly.dev"
            },
        )

        service = ecs.FargateService(
            self,
            f"{self.name}-FrontendService",
            cluster=cluster,
            task_definition=task_definition,
            security_groups=[ecs_sg],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC,
            ),
            desired_count=1,
            min_healthy_percent=50,
            max_healthy_percent=200,
            circuit_breaker=ecs.DeploymentCircuitBreaker(
                rollback=True,
                enable=True
            ),
            enable_execute_command=not self.is_production,
            assign_public_ip=True,
        )

        alb = ApplicationLoadBalancer(
            self,
            f"{self.name}-FrontendALB",
            vpc=vpc,
            internet_facing=True,
            security_group=alb_sg,
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PUBLIC,
            ),
        )

        listener = alb.add_listener(
            f"{self.name}-FrontendListener",
            port=443,
            open=True,
            protocol=ApplicationProtocol.HTTPS,
            certificates=[self.certificate],
        )
        listener.add_targets(
            f"{self.name}-FrontendTargetGroup",
            port=80,
            targets=[service],
            health_check=HealthCheck(
                path="/",
                interval=Duration.seconds(30),
                timeout=Duration.seconds(5),
                healthy_threshold_count=2,
                unhealthy_threshold_count=2,
            ),
        )

        alb.add_listener(
            f"{self.name}-FrontendHttpListener",
            port=80,
            open=True,
            default_action=ListenerAction.redirect(
                host=self.fqdn,
                port="443",
                protocol="HTTPS",
                permanent=True,
            ),
        )

        web_acl_frontend = create_waf_scope_web_acl(self, f"{self.name}-FrontendWebACL", name=f"{self.name}-Frontend", scope_type="REGIONAL", log_bucket=self.log_bucket)
        CfnWebACLAssociation(
            self,
            f"{self.name}-FrontendWebACLAssociation",
            resource_arn=alb.load_balancer_arn,
            web_acl_arn=web_acl_frontend.attr_arn
        )

        if self.node.try_get_context("isRoute53Domain"):
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=self.node.try_get_context('domainName'))

            route53.ARecord(
                self,
                f"{self.name}-FrontendAliasRecord",
                zone=zone,
                record_name=self.fqdn,
                target=route53.RecordTarget.from_alias(route53_targets.LoadBalancerTarget(alb)),
            )
        else:
            CfnOutput(self, "FrontendCNAME", value=f"{self.fqdn} -> {alb.load_balancer_dns_name}")

        CfnOutput(self, "FrontendUrl", value=f"https://{self.fqdn}")
