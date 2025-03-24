from aws_cdk import (
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_cloudfront as cloudfront,
    aws_cloudfront_origins as origins,
    aws_codebuild as codebuild,
    aws_iam as iam,
    aws_codepipeline as codepipeline,
    aws_codepipeline_actions as cpactions,
    aws_codecommit as codecommit,
    aws_codebuild as cb,
    aws_ec2 as ec2,
    RemovalPolicy,
    Duration,
)
from constructs import Construct


class GalvFrontend(Construct):
    def __init__(self, scope: Construct, id: str, *, vpc: ec2.Vpc) -> None:
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
        )

        distribution = cloudfront.Distribution(
            self,
            f"{name}-FrontendCDN",
            default_behavior=cloudfront.BehaviorOptions(
                origin=origins.S3BucketOrigin(website_bucket),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
            ),
        )

        # === CodeBuild Project ===
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
                    "install": {
                        "commands": [
                            "npm install"
                        ]
                    },
                    "build": {
                        "commands": [
                            "npm run build"
                        ]
                    }
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
            )
        )
