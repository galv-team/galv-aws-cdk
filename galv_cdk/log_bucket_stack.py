from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_s3 as s3, Tags,
)
from cdk_nag import NagSuppressions
from constructs import Construct


class LogBucketStack(Stack):
    def __init__(self, scope: Construct, id: str, *, name: str, is_production: bool, **kwargs):
        super().__init__(scope, id, **kwargs)

        project_tag = self.node.try_get_context("projectNameTag") or "galv"
        self.env = kwargs.get("env")
        self.name = name
        self.is_production = is_production

        self.log_bucket = s3.Bucket(
            self,
            f"{name}-LogBucket",
            bucket_name=f"{name}-LogBucket".lower(),
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=RemovalPolicy.RETAIN if is_production else RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            auto_delete_objects=not is_production,
        )

        Tags.of(self).add("project-name", project_tag)

        # Add CDK Nag rules
        NagSuppressions.add_resource_suppressions(
            self.log_bucket,
            [
                {
                    "id": "AwsSolutions-S10",
                    "reason": "ALB access logs require a bucket without enforced aws:SecureTransport policies; encryption is still applied using S3-managed keys."
                },
                {
                    "id": "AwsSolutions-S1",
                    "reason": "Log bucket is not itself logged to avoid circular logging"
                },
                {
                    "id": "HIPAA.Security-S3BucketLoggingEnabled",
                    "reason": "Log bucket is not itself logged to avoid circular logging"
                },
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "Log data is append-only; versioning not required"
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "Cross-region replication not needed for logs"
                },
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": "ALB access logs cannot be delivered to a KMS-encrypted bucket; S3-managed encryption is used instead."
                }
            ]
        )
        NagSuppressions.add_resource_suppressions(
            self.log_bucket.node.default_child,
            [
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": "ALB access logs cannot be delivered to a KMS-encrypted bucket; S3-managed encryption is used instead."
                },
            ]
        )
