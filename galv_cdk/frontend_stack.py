from aws_cdk import (
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_codebuild as codebuild,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    aws_certificatemanager as acm,
    RemovalPolicy,
    Stack, CfnOutput, Environment, Tags,
)
from cdk_nag import NagSuppressions
from constructs import Construct

from nag_supressions import suppress_nags_pre_synth
from utils import create_waf_scope_web_acl, get_aws_custom_cert_instructions


class GalvFrontend(Stack):
    """
    This all happens in US-East-1 because CloudFront is a global service.
    """
    def __init__(self, scope: Construct, id: str, *, certificate_arn: str = None, **kwargs) -> None:
        env = kwargs.get("env", {})
        env["region"] = "us-east-1"
        try:
            del kwargs["env"]
        except KeyError:
            pass
        super().__init__(scope, id, env=Environment(**env), **kwargs)

        self.name = self.node.try_get_context("name") or "galv"
        project_tag = self.node.try_get_context("projectNameTag") or "galv"
        self.domain_name=self.node.get_context("domainName")
        subdomain=self.node.get_context("frontendSubdomain")
        self.fqdn = f"{subdomain}.{self.domain_name}".lstrip(".")

        try:
            self.is_route53_domain = self.node.get_context("isRoute53Domain")
        except KeyError:
            self.is_route53_domain = True

        self.certificate_arn = certificate_arn

        self.log_bucket = s3.Bucket(
            self,
            f"{self.name}-FrontendLogBucket",
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

        self._create_bucket()
        self._create_domain_certificates()
        self._create_web_acl()
        self._create_cloudfront()
        self._create_codebuild()

        Tags.of(self).add("project-name", project_tag)

        suppress_nags_pre_synth(self)

    def _create_bucket(self):
        is_production = self.node.try_get_context("isProduction")
        if is_production is None:
            is_production = True

        removal_policy = RemovalPolicy.RETAIN if is_production else RemovalPolicy.DESTROY
        auto_delete = False if is_production else True

        self.website_bucket = s3.Bucket(
            self,
            f"{self.name}-FrontendBucket",
            website_index_document="index.html",
            removal_policy=removal_policy,
            auto_delete_objects=auto_delete,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=self.log_bucket,
            server_access_logs_prefix=f"{self.name}-FrontendStorage-access-logs/",
        )

        self.website_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:*"],
                effect=iam.Effect.DENY,
                principals=[iam.StarPrincipal()],
                resources=[
                    self.website_bucket.bucket_arn,
                    self.website_bucket.arn_for_objects("*"),
                ],
                conditions={"Bool": {"aws:SecureTransport": "false"}},
            )
        )

    def _create_domain_certificates(self):
        # Create the CDK app with the loaded context
        if self.certificate_arn is None and not self.is_route53_domain:
            raise ValueError(get_aws_custom_cert_instructions(self.fqdn))

        if self.is_route53_domain:
            zone = route53.HostedZone.from_lookup(self, f"{self.name}-FrontendHostedZone", domain_name=self.domain_name)
            self.certificate = acm.Certificate(
                self,
                f"{self.name}-FrontendCertificate",
                domain_name=self.fqdn,
                validation=acm.CertificateValidation.from_dns(zone),
            )
        else:
            self.certificate = acm.Certificate.from_certificate_arn(self, f"{self.name}-FrontendCertificate", self.certificate_arn)

    def _create_web_acl(self):
        """
        Create a WAFv2 WebACL for CloudFront with logging enabled.
        """
        self.web_acl = create_waf_scope_web_acl(self, f"{self.name}-FrontendWebACL", name="cloudfront-acl", scope_type="CLOUDFRONT", log_bucket=self.log_bucket)

        NagSuppressions.add_resource_suppressions(
            self.log_bucket,
            [
                {
                    "id": "AwsSolutions-S1",
                    "reason": "Server access logs are not needed on this bucket because it only receives logs (e.g., from WAF)."
                },
                {
                    "id": "HIPAA.Security-S3BucketLoggingEnabled",
                    "reason": "This bucket only receives WAF logs and is not accessed directly."
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "Replication is not required for non-critical WAF log data."
                },
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "Versioning not needed for append-only log destination."
                },
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": "S3-managed encryption is sufficient for WAF logs."
                }
            ]
        )

    def _create_cloudfront(self):
        self.frontend_oac = cloudfront.CfnOriginAccessControl(
            self,
            f"{self.name}-FrontendOAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name="FrontendOAC",
                origin_access_control_origin_type="s3",
                signing_behavior="always",
                signing_protocol="sigv4",
                description="Access control for frontend bucket"
            )
        )

        self.waf_arn = self.node.try_get_context("frontendWafArn")

        self.distribution = cloudfront.Distribution(
            self,
            f"{self.name}-FrontendCDN",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin(
                    self.website_bucket,
                    origin_access_control_id=self.frontend_oac.attr_id
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
            enable_logging=True,
            log_bucket=self.log_bucket,
            log_file_prefix=f"{self.name}-FrontendCDN-logs/",
            web_acl_id=self.waf_arn,
            domain_names=[self.fqdn],
            certificate=self.certificate
        )

        # Add Route 53 alias record for the CloudFront distribution
        if self.is_route53_domain:
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=self.domain_name)
            route53.ARecord(
                self,
                f"{self.name}-FrontendAliasRecord",
                zone=zone,
                record_name=self.fqdn,
                target=route53.RecordTarget.from_alias(
                    route53_targets.CloudFrontTarget(self.distribution)
                )
            )
        else:
            CfnOutput(self, "FrontendCNAME", value=f"{self.fqdn} -> {self.distribution.distribution_domain_name}")

        # Add a policy to allow CloudFront to access the S3 bucket
        self.website_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[self.website_bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{Stack.of(self).account}:distribution/{self.distribution.distribution_id}"
                    }
                }
            )
        )

    def _create_codebuild(self):
        frontend_version = self.node.try_get_context("frontendVersion") or "latest"

        self.build_project = codebuild.Project(
            self,
            f"{self.name}-FrontendBuild",
            source=codebuild.Source.git_hub(
                owner="galv-team",
                repo="galv-frontend",
                clone_depth=1,
                fetch_submodules=False,
                branch_or_ref=frontend_version,
            ),
            environment=codebuild.BuildEnvironment(
                build_image=codebuild.LinuxBuildImage.STANDARD_7_0,
                privileged=False,
            ),
            subnet_selection=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PUBLIC),
            build_spec=codebuild.BuildSpec.from_object({
                "version": "0.2",
                "phases": {
                    "install": {"commands": ["npm install"]},
                    "build": {"commands": ["npm run build"]}
                },
                "artifacts": {
                    "base-directory": "build",
                    "files": ["**/*"]
                }
            }),
            artifacts=codebuild.Artifacts.s3(
                bucket=self.website_bucket,
                package_zip=False,
                include_build_id=False,
            ),
            logging=codebuild.LoggingOptions(
                s3=codebuild.S3LoggingOptions(
                    bucket=self.log_bucket,
                    prefix=f"{self.name}-FrontendBuild-logs"
                ),
            ),
        )
