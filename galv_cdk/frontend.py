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
    Duration, Stack, CfnOutput,
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

        web_acl_frontend = create_waf_scope_web_acl(self, "FrontendWebACL", name="frontend", scope_type="CLOUDFRONT", log_bucket=log_bucket)

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

        NagSuppressions.add_resource_suppressions(
            website_bucket,
            suppressions=[
                {"id": "AwsSolutions-S1", "reason": "No need for server access logs on public static bucket"},
                {"id": "AwsSolutions-S10", "reason": "HTTPS is enforced at CloudFront level, not S3"},
                {"id": "HIPAA.Security-S3BucketReplicationEnabled", "reason": "Replication not needed for this bucket"},
                {"id": "HIPAA.Security-S3DefaultEncryptionKMS", "reason": "Static assets only; encryption not required"},
                {"id": "HIPAA.Security-S3BucketVersioningEnabled", "reason": "Frontend code is immutable; versioning unnecessary"}
            ]
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
            web_acl_id=web_acl_frontend.attr_arn,
            domain_names=[fqdn],
            certificate=certificate
        )
        NagSuppressions.add_resource_suppressions(
            distribution.node.default_child,
            suppressions=[
                {
                    "id": "AwsSolutions-CFR1",
                    "reason": "Geo restrictions are not required for this public static site."
                },
            ],
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
        NagSuppressions.add_resource_suppressions(
            website_bucket,
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Wildcard is required to allow CloudFront access to all objects in the website bucket. "
                        "Access is limited to a specific CloudFront distribution via AWS:SourceArn."
                    ),
                    "applies_to": [f"Resource::{website_bucket.bucket_arn}/*"]
                },
                {
                    "id": "AwsSolutions-S5",
                    "reason": "This bucket uses OAC with signed requests from CloudFront. Access is restricted via bucket policy."
                }
            ],
            apply_to_children=True
        )
        NagSuppressions.add_resource_suppressions(
            website_bucket.policy,
            suppressions=[
                {
                    "id": "AwsSolutions-S10",
                    "reason": "The bucket enforces SSL via a deny policy on non-SecureTransport requests."
                },
                {
                    "id": "HIPAA.Security-S3BucketSSLRequestsOnly",
                    "reason": "The bucket enforces SSL via a deny policy on non-SecureTransport requests."
                }
            ]
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
                    prefix=f"{name}-FrontendBuild-logs/"
                ),
            ),
        )

        NagSuppressions.add_resource_suppressions(
            build_project.role.node.find_child("DefaultPolicy"),
            suppressions=[
                {
                    "id": "AwsSolutions-IAM5",
                    "appliesTo": [
                        f"Resource::{website_bucket.bucket_arn}",
                        f"Resource::{website_bucket.arn_for_objects('*')}"
                    ],
                    "reason": "Wildcard resource scoped to specific S3 bucket used for frontend build artifacts"
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "appliesTo": [
                        f"Action::s3:GetObject*",
                        f"Action::s3:GetBucket*",
                        f"Action::s3:List*",
                        f"Action::s3:DeleteObject*",
                        f"Action::s3:Abort*",
                        f"Resource::{website_bucket.bucket_arn}/*",
                    ],
                    "reason": "Frontend build artifacts are deployed to S3 via CodeBuild Artifacts.s3(), which uses these permissions."
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Wildcard access to log bucket objects is used by CodeBuild for access logs and artifact staging."
                    ),
                    "applies_to": [f"Resource::{log_bucket.bucket_arn}/*"]
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Wildcard permissions are required by CodeBuild to interact with network interfaces, log groups, "
                        "and report groups with dynamic names generated at deployment time."
                    ),
                    "applies_to": [
                        "Resource::arn:<AWS::Partition>:ec2:<AWS::Region>:<AWS::AccountId>:network-interface/*",
                        f"Resource::arn:<AWS::Partition>:logs:{Stack.of(self).region}:{Stack.of(self).account}:log-group:/aws/codebuild/{build_project.project_name}:*",
                        f"Resource::arn:<AWS::Partition>:codebuild:{Stack.of(self).region}:{Stack.of(self).account}:report-group/{build_project.project_name}-*"
                    ]
                }
            ]
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

