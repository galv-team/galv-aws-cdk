import secrets
import string

from aws_cdk import Stack, Environment
from aws_cdk.aws_s3 import IBucket
from cdk_nag import NagSuppressions
from constructs import IConstruct
import aws_cdk.aws_wafv2 as wafv2
import aws_cdk.aws_iam as iam
from aws_cdk.custom_resources import AwsCustomResource


def generate_django_secret_key(length: int = 50) -> str:
    allowed_chars = string.ascii_letters + string.digits + string.punctuation
    allowed_chars = allowed_chars.replace('"', '').replace("'", '').replace('\\', '')
    return ''.join(secrets.choice(allowed_chars) for _ in range(length))


def inject_protected_env(env: dict, protected: dict):
    """
    Inject protected environment variables into an environment dictionary, raising an error if any of the protected
    variables are already set.
    """
    for key, value in protected.items():
        if key in env:
            raise ValueError(f"You cannot specify reserved environment variable '{key}'.")
        env[key] = value


def print_nag_findings(scope: IConstruct):
    for node in scope.node.children:
        # Recurse into child nodes
        print_nag_findings(node)

        # Look for metadata entries attached by cdk-nag
        metadata = node.node.metadata
        for entry in metadata:
            if entry.type == "aws:cdk:warning":
                print(f"[Warning] {node.node.path}: {entry.data}")
            elif entry.type == "aws:cdk:error":
                print(f"[Error] {node.node.path}: {entry.data}")


def create_waf_scope_web_acl(scope, id, *, name: str, scope_type: str, log_bucket: IBucket) -> wafv2.CfnWebACL:
    """
    Create a basic AWS WAFv2 WebACL with managed rule groups for either CLOUDFRONT (global)
    or REGIONAL (for ALB).

    SIDE EFFECT: Adds a resource policy to the log bucket to allow WAF to write logs.

    :param scope: CDK Construct scope
    :param id: CDK resource ID
    :param name: Name prefix for the WebACL
    :param scope_type: 'REGIONAL' for ALB, 'CLOUDFRONT' for CloudFront
    :param log_bucket: S3 bucket for logging
    :return: CfnWebACL resource
    """

    # log_bucket.add_to_resource_policy(iam.PolicyStatement(
    #     sid="AWSWAFLoggingPermissions",
    #     actions=["s3:PutObject"],
    #     resources=[log_bucket.arn_for_objects("AWSLogs/*")],
    #     principals=[iam.ServicePrincipal("logging.s3.amazonaws.com")],
    #     conditions={
    #         "StringEquals": {
    #             "aws:SourceAccount": Stack.of(scope).account
    #         },
    #         "ArnLike": {
    #             "aws:SourceArn": f"arn:aws:wafv2:{Stack.of(scope).region}:{Stack.of(scope).account}:*/webacl/*"
    #         }
    #     }
    # ))

    waf = wafv2.CfnWebACL(
        scope,
        id,
        default_action=wafv2.CfnWebACL.DefaultActionProperty(allow={}),
        scope=scope_type,
        visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
            sampled_requests_enabled=True,
            cloud_watch_metrics_enabled=True,
            metric_name=f"{name}-waf-metrics"
        ),
        name=f"{name}-waf",
        rules=[
            wafv2.CfnWebACL.RuleProperty(
                name=f"{name}-AWSManagedRulesCommonRuleSet",
                priority=0,
                override_action=wafv2.CfnWebACL.OverrideActionProperty(none={}),
                statement=wafv2.CfnWebACL.StatementProperty(
                    managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                        name="AWSManagedRulesCommonRuleSet",
                        vendor_name="AWS"
                    ),
                    rule_action_overrides=[
                        wafv2.CfnWebACL.RuleActionOverrideProperty(
                            name="SizeRestrictions_BODY",
                            action=wafv2.CfnWebACL.RuleActionProperty(count={}),
                        )
                    ],
                ),
                visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                    sampled_requests_enabled=True,
                    cloud_watch_metrics_enabled=True,
                    metric_name=f"{name}-CommonRuleSet"
                )
            )
        ]
    )

    NagSuppressions.add_resource_suppressions(
        waf,
        [{
            "id": "HIPAA.Security-WAFv2LoggingEnabled",
            "reason": "Logging is not required for this WAF; access is controlled via ALB security group or CloudFront"
        }],
        apply_to_children=True
    )

    # wafv2.CfnLoggingConfiguration(
    #     scope,
    #     f"{name}-WebAclLogging",
    #     log_destination_configs=[log_bucket.bucket_arn],
    #     resource_arn=waf.attr_arn,
    # )

    return waf

def get_aws_custom_cert_instructions(fqdn: str):
    """
    Generate instructions for creating an AWS Certificate Manager (ACM) certificate for a given domain name (FQDN).
    The instructions include the command to create the certificate and the command to validate it using DNS.
    """
    return f"""No certificate ARN was provided, and this domain ({fqdn}) is not managed by Route53, so CDK cannot create and validate
a certificate automatically.
To proceed, you must manually create a certificate in AWS Certificate Manager (ACM).
Instructions:
1. In the AWS Console, switch to the region: us-east-1 (required for CloudFront certificates).
2. Navigate to AWS Certificate Manager (ACM).
3. Request a new public certificate for the domain:
       {fqdn}
4. Choose "DNS Validation".
5. Complete the DNS setup as instructed (you will add a CNAME to your DNS provider).
6. Once the certificate status shows "Issued", copy the certificate ARN.
Then re-run the CDK deployment with the certificate ARN provided via context:
    --context certificateArn=arn:aws:acm:us-east-1:<account-id>:certificate/<uuid>
You can also store it in `cdk.json` like:
    "context": {{
        "certificateArn": "arn:aws:acm:us-east-1:<account-id>:certificate/<uuid>"
    }}
This step is required because CloudFormation cannot manage DNS validation for domains not hosted in Route53.
    """
