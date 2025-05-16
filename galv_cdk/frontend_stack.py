from aws_cdk import (
    Stack, CfnOutput,
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_ecs as ecs,
    aws_ecs_patterns as ecs_patterns,
    aws_certificatemanager as acm,
    aws_route53 as route53,
    aws_logs as logs,
    aws_iam as iam,
    aws_s3 as s3, RemovalPolicy,
)
from constructs import Construct
from nag_supressions import suppress_nags_pre_synth
from utils import get_aws_custom_cert_instructions, create_waf_scope_web_acl

class GalvFrontend(Stack):
    def __init__(self, scope: Construct, id: str, certificate_arn: str = None, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        self.name = self.node.try_get_context("name") or "galv"
        self.project_tag = self.node.try_get_context("projectNameTag") or "galv"
        self.is_production = self.node.try_get_context("isProduction") or True
        self.domain_name = self.node.get_context("domainName")
        self.subdomain = self.node.get_context("frontendSubdomain")
        self.fqdn = f"{self.subdomain}.{self.domain_name}".lstrip(".")
        self.is_route53_domain = self.node.try_get_context("isRoute53Domain") or False
        self.frontend_version = self.node.try_get_context("frontendVersion") or "latest"

        self._create_log_bucket()
        self._create_cert(certificate_arn)
        self._create_vpc()
        self._create_cluster()
        self._create_service()

        suppress_nags_pre_synth(self)

    def _create_log_bucket(self):
        """
        Create an S3 Bucket for storing logs.
        Some logs are stored in the bucket, and some are sent to CloudWatch, because not all logs can be sent to S3.
        :return:
        """
        # ==== Log Bucket ====
        self.log_bucket = s3.Bucket(
            self,
            f"{self.name}-LogBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            auto_delete_objects=not self.is_production,
        )

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
        if certificate_arn:
            self.certificate = acm.Certificate.from_certificate_arn(
                self, "FrontendCertificate", certificate_arn
            )
        elif self.is_route53_domain:
            zone = route53.HostedZone.from_lookup(self, "FrontendZone", domain_name=self.domain_name)
            self.certificate = acm.Certificate(
                self,
                "FrontendCertificate",
                domain_name=self.fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )
        else:
            raise ValueError(get_aws_custom_cert_instructions(self.fqdn))

    def _create_vpc(self):
        self.vpc = ec2.Vpc(
            self,
            f"{self.name}-FrontendVpc",
            max_azs=2,
            nat_gateways=0,
            subnet_configuration=[
                ec2.SubnetConfiguration(name="public", subnet_type=ec2.SubnetType.PUBLIC),
                ec2.SubnetConfiguration(name="private", subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            ],
            flow_logs={
                "AllTraffic": ec2.FlowLogOptions(
                    destination=ec2.FlowLogDestination.to_s3(self.log_bucket)
                )
            }
        )

    def _create_cluster(self):
        self.cluster = ecs.Cluster(self, f"{self.name}-FrontendCluster", vpc=self.vpc)

    def _create_service(self):
        web_acl = create_waf_scope_web_acl(
            self, f"{self.name}-FrontendWAF", name=f"{self.name}-frontend", scope_type="REGIONAL", log_bucket=None
        )

        log_group = logs.LogGroup(
            self,
            f"{self.name}-FrontendLogGroup",
            retention=logs.RetentionDays.ONE_YEAR if self.is_production else logs.RetentionDays.ONE_DAY,
        )

        repo = ecr.Repository.from_repository_name(
            self,
            f"{self.name}-FrontendRepo",
            repository_name="galv-frontend"
        )

        service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self,
            f"{self.name}-FrontendService",
            cluster=self.cluster,
            cpu=256,
            memory_limit_mib=512,
            desired_count=1,
            public_load_balancer=True,
            certificate=self.certificate,
            domain_name=self.fqdn,
            domain_zone=route53.HostedZone.from_lookup(self, "Zone", domain_name=self.domain_name),
            redirect_http=True,
            task_image_options=ecs_patterns.ApplicationLoadBalancedTaskImageOptions(
                image=ecs.ContainerImage.from_ecr_repository(
                    repository=repo,
                    tag=self.frontend_version
                ),
                container_port=80,
                log_driver=ecs.LogDrivers.aws_logs(
                    stream_prefix="galv-frontend",
                    log_group=log_group,
                ),
            ),
        )

        # Attach WAF to ALB
        alb = service.load_balancer.node.default_child
        alb.add_property_override(
            "WebACLId", web_acl.ref
        )

        # Secure ALB headers + optional output
        alb.add_property_override("LoadBalancerAttributes", [
            {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"},
            {"Key": "deletion_protection.enabled", "Value": str(self.is_production).lower()}
        ])

        CfnOutput(self, "FrontendUrl", value=f"https://{self.fqdn}")
