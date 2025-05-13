from aws_cdk import (
    aws_s3 as s3,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_codebuild as codebuild,
    aws_iam as iam,
    aws_ec2 as ec2,
    aws_route53 as route53,
    aws_route53_targets as route53_targets,
    RemovalPolicy,
    Duration, Stack, CfnOutput, NestedStack, Environment,
)
from aws_cdk.aws_certificatemanager import ICertificate, Certificate
from cdk_nag import NagSuppressions
from constructs import Construct

from utils import create_waf_scope_web_acl


class GalvFrontend(Construct):
    def __init__(self, scope: Construct, id: str, *, vpc: ec2.Vpc, log_bucket: s3.Bucket | s3.IBucket, fqdn: str, certificate: ICertificate|Certificate) -> None:
        super().__init__(scope, id)

        name = self.node.try_get_context("name") or "galv"
        frontend_version = self.node.try_get_context("frontendVersion") or "latest"
        is_production = self.node.try_get_context("isProduction")
        if is_production is None:
            is_production = True

        removal_policy = RemovalPolicy.RETAIN if is_production else RemovalPolicy.DESTROY
        auto_delete = False if is_production else True

        website_bucket = s3.Bucket(
            self,
            f"{name}-FrontendBucket",
            website_index_document="index.html",
            removal_policy=removal_policy,
            auto_delete_objects=auto_delete,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            server_access_logs_bucket=log_bucket,
            server_access_logs_prefix=f"{name}-BackendStorage-access-logs/",
        )

        website_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:*"],
                effect=iam.Effect.DENY,
                principals=[iam.StarPrincipal()],
                resources=[
                    website_bucket.bucket_arn,
                    website_bucket.arn_for_objects("*"),
                ],
                conditions={"Bool": {"aws:SecureTransport": "false"}},
            )
        )

        frontend_oac = cloudfront.CfnOriginAccessControl(
            self,
            "FrontendOAC",
            origin_access_control_config=cloudfront.CfnOriginAccessControl.OriginAccessControlConfigProperty(
                name="FrontendOAC",
                origin_access_control_origin_type="s3",
                signing_behavior="always",
                signing_protocol="sigv4",
                description="Access control for frontend bucket"
            )
        )

        waf_arn = self.node.try_get_context("frontendWafArn")

        distribution = cloudfront.Distribution(
            self,
            f"{name}-FrontendCDN",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin(
                    website_bucket,
                    origin_access_control_id=frontend_oac.attr_id
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
            enable_logging=True,
            log_bucket=log_bucket,
            log_file_prefix=f"{name}-FrontendCDN-logs/",
            web_acl_id=waf_arn,
            domain_names=[fqdn],
            certificate=certificate
        )

        website_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                actions=["s3:GetObject"],
                resources=[website_bucket.arn_for_objects("*")],
                principals=[iam.ServicePrincipal("cloudfront.amazonaws.com")],
                conditions={
                    "StringEquals": {
                        "AWS:SourceArn": f"arn:aws:cloudfront::{Stack.of(self).account}:distribution/{distribution.distribution_id}"
                    }
                }
            )
        )

        build_project = codebuild.Project(
            self,
            f"{name}-FrontendBuild",
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
            vpc=vpc,
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
                bucket=website_bucket,
                path="/",
                package_zip=False,
                include_build_id=False,
            ),
            logging=codebuild.LoggingOptions(
                s3=codebuild.S3LoggingOptions(
                    bucket=log_bucket,
                    prefix=f"{name}-FrontendBuild-logs"
                ),
            ),
        )

        if self.node.try_get_context('isRoute53Domain'):
            zone = route53.HostedZone.from_lookup(self, "HostedZone", domain_name=self.node.try_get_context('domainName'))

            # Add Route 53 alias record for the CloudFront distribution
            route53.RecordSet(
                self,
                f"{name}-FrontendRoute53Record",
                record_type=route53.RecordType.A,
                target=route53.RecordTarget.from_alias(
                    route53_targets.CloudFrontTarget(distribution)
                ),
                zone=zone,
                record_name=fqdn,
            )
        else:
            CfnOutput(self, "FrontendCNAME", value=f"{fqdn} -> {distribution.distribution_domain_name}")

