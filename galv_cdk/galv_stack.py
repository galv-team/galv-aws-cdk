from aws_cdk import Stack, Tags, RemovalPolicy
from aws_cdk import aws_ec2 as ec2, aws_s3 as s3, aws_iam as iam, aws_kms as kms, aws_certificatemanager as acm, \
    aws_route53 as route53
from constructs import Construct

from galv_cdk.backend import GalvBackend
from galv_cdk.frontend import GalvFrontend
from nag_supressions import suppress_nags_pre_synth


class GalvStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, certificate_arn: str|None = None, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        project_tag = self.node.try_get_context("projectNameTag") or "galv"
        self.name = self.node.try_get_context("name") or "galv"
        self.is_production = self.node.try_get_context("isProduction")
        if self.is_production is None:
            self.is_production = True

        self.certificate_arn = certificate_arn

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

        self._create_domain_certificates()
        self._create_log_bucket()
        self._create_vpc()

        # ==== Frontend Deployment ====
        GalvFrontend(self, f"{self.name}-Frontend", vpc=self.vpc, log_bucket=self.log_bucket, fqdn=self.frontend_fqdn, certificate=self.frontend_cert)

        # ==== Backend Deployment ====
        self.backend = GalvBackend(self, f"{self.name}-Backend", vpc=self.vpc, log_bucket=self.log_bucket, kms_key=self.kms_key, fqdn=self.backend_fqdn, backend_cert=self.backend_cert)
        self.backend.node.add_dependency(self.kms_key)

        Tags.of(self).add("project-name", project_tag)

        suppress_nags_pre_synth(self)

    def _create_domain_certificates(self):
        domain_name = self.node.try_get_context("domainName")
        frontend_subdomain = self.node.try_get_context("frontendSubdomain") or ""
        backend_subdomain = self.node.try_get_context("backendSubdomain") or "api"
        is_route53_domain = self.node.try_get_context("isRoute53Domain")
        if is_route53_domain is None:
            is_route53_domain = True

        self.frontend_fqdn = f"{frontend_subdomain}.{domain_name}".lstrip(".")
        self.backend_fqdn = f"{backend_subdomain}.{domain_name}".lstrip(".")

        if self.frontend_fqdn == self.backend_fqdn:
            raise ValueError("Frontend and backend domain names cannot be the same")

        if self.certificate_arn:
            # Use existing certificate ARN if provided
            self.frontend_cert = acm.Certificate.from_certificate_arn(self, f"{self.name}-FrontendCertificate", self.certificate_arn)
            self.backend_cert = acm.Certificate.from_certificate_arn(self, f"{self.name}-BackendCertificate", self.certificate_arn)
        else:
            if not is_route53_domain:
                raise ValueError("Route53 must manage the domain if no certificate ARN is provided.")

            # Use DNS validation with Route 53
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=domain_name)

            self.frontend_cert = acm.Certificate(
                self,
                f"{self.name}-FrontendCertificate",
                domain_name=self.frontend_fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )

            self.backend_cert = acm.Certificate(
                self,
                "BackendCertificate",
                domain_name=self.backend_fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )

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
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL
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

    def _create_vpc(self):
        """
        Create a VPC with public, private, and isolated subnets.
        Public subnets are used for the ALB, private subnets are used for the backend services, and isolated subnets are used for the database.
        :return:
        """

        # ==== Shared VPC ====
        self.vpc = ec2.Vpc(
            self,
            f"{self.name}-Vpc",
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    map_public_ip_on_launch=False,
                ),
                ec2.SubnetConfiguration(
                    name="private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                ),
                ec2.SubnetConfiguration(
                    name="isolated",
                    subnet_type=ec2.SubnetType.PRIVATE_ISOLATED,
                )
            ],
            nat_gateways=0,  # Avoid NAT gateway charges
            flow_logs={
                "AllTraffic": ec2.FlowLogOptions(
                    destination=ec2.FlowLogDestination.to_s3(self.log_bucket)
                )
            },
        )

        # Add interface endpoints for private access to AWS services
        vpc_endpoint_sg = ec2.SecurityGroup(self, f"{self.name}-EndpointSG", vpc=self.vpc)
        vpc_endpoint_sg.add_ingress_rule(ec2.Peer.ipv4(self.vpc.vpc_cidr_block), ec2.Port.tcp(443), "HTTPS from VPC")

        self.vpc.add_interface_endpoint(
            "SecretsManagerEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
            security_groups=[vpc_endpoint_sg],
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )

        self.vpc.add_interface_endpoint(
            "CloudWatchLogsEndpoint",
            service=ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
            security_groups=[vpc_endpoint_sg],
            subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
        )
