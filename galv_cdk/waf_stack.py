from aws_cdk import Stack, Environment, RemovalPolicy, CfnOutput
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_iam as iam
from cdk_nag import NagSuppressions
from constructs import Construct

from utils import create_waf_scope_web_acl


class FrontendWafStack(Stack):
    """
    CloudFront WAF stacks are always created in the us-east-1 region.
    """
    def __init__(self, scope: Construct, id: str, name: str, **kwargs):
        super().__init__(scope, id, env=Environment(region="us-east-1"), **kwargs)

        self.log_bucket = s3.Bucket(
            self,
            f"{name}-FrontendWebACLLogBucket",
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

        self.web_acl = create_waf_scope_web_acl(self, f"{name}-FrontendWebACL", name=name, scope_type="CLOUDFRONT", log_bucket=self.log_bucket)

        CfnOutput(self, "FrontendWafArn", value=self.web_acl.attr_arn)

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
