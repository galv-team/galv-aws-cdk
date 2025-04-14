from cdk_nag import NagSuppressions, NagPackSuppression
from aws_cdk import Stack, Fn


class InapplicableSuppressionError(Exception):
    pass


def suppress_nags(stack: Stack, name: str):
    """
    Apply centralized CDK Nag suppressions to known resources based on {name}.
    This should be called after all constructs are created.
    """
    if not stack.node.try_get_context("isRoute53Domain"):
        _suppress_cert_stack(stack)

    _suppress_frontend(stack, name)
    _suppress_backend_taskrole_policy(stack, name)
    _suppress_vpc_endpoints(stack, name)
    _suppress_codebuild(stack, name)
    _suppress_frontend_bucket_policy(stack, name)
    _suppress_log_bucket(stack, name)
    _suppress_backend_bucket(stack, name)
    _suppress_backend_iams(stack, name)
    _suppress_frontend_iam(stack, name)
    _suppress_frontend_bucket(stack, name)
    _suppress_vpc_routes(stack, name)
    _suppress_secret_rotation(stack, name)
    _suppress_ecs_env_vars(stack, name)
    _suppress_inline_iam_policies(stack, name)
    _suppress_ecs_iam5_wildcards(stack, name)


def _suppress_cert_stack(stack: Stack):
    try:
        cert = stack.node.find_child("Certificate")
        NagSuppressions.add_resource_suppressions(cert, [
            {"id": "AwsSolutions-ACM1", "reason": "Certificate is DNS validated."}
        ])
    except Exception as e:
        is_route53_domain = stack.node.try_get_context("isRoute53Domain")
        if is_route53_domain is False:
            raise InapplicableSuppressionError("Certificate not found") from e


def _suppress_frontend(stack: Stack, name: str):
    try:
        frontend = stack.node.find_child("Frontend")
        cdn = frontend.node.find_child(f"{name}-FrontendCDN")
        NagSuppressions.add_resource_suppressions(
            cdn.node.default_child,
            [{
                "id": "AwsSolutions-CFR1",
                "reason": "Geo restrictions are not required for this public static site."
            }]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Frontend CDN not found") from e


def _suppress_backend_taskrole_policy(stack: Stack, name: str):
    try:
        backend = stack.node.find_child("Backend")
        service = backend.node.find_child(f"{name}-BackendService")
        task_role = service.task_definition.task_role
        default_policy = task_role.node.find_child("DefaultPolicy")

        if default_policy is None:
            raise InapplicableSuppressionError("DefaultPolicy not attached to TaskRole")

        NagSuppressions.add_resource_suppressions(
            default_policy,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Backend service needs wildcard S3 access for dynamic media paths",
                    "appliesTo": [
                        "Action::s3:GetObject*",
                        f"Resource::arn:aws:s3:::{name}-BackendStorage/*"
                    ]
                }
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Backend task role suppression failed") from e


def _suppress_vpc_endpoints(stack: Stack, name: str):
    try:
        sg = stack.node.find_child(f"{name}-EndpointSG")
        NagSuppressions.add_resource_suppressions(
            sg,
            [
                {
                    "id": "AwsSolutions-EC23",
                    "reason": "CDK Nag cannot evaluate VPC CIDR block when used in ingress rule. Ingress is correctly scoped to internal HTTPS only."
                },
                {
                    "id": "HIPAA.Security-EC2RestrictedCommonPorts",
                    "reason": "443 ingress is internal-only; CDK Nag cannot evaluate CIDR scope."
                },
                {
                    "id": "HIPAA.Security-EC2RestrictedSSH",
                    "reason": "Rule only allows port 443. SSH is not open."
                },
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("VPC endpoint SG not found") from e


def _suppress_codebuild(stack: Stack, name: str):
    try:
        frontend = stack.node.find_child("Frontend")
        project = frontend.node.find_child(f"{name}-FrontendBuild")
        policy = project.role.node.find_child("DefaultPolicy")

        if policy is None:
            raise InapplicableSuppressionError("CodeBuild DefaultPolicy not found")

        project_logical_id = stack.get_logical_id(project.node.default_child)
        region = stack.region
        account = stack.account

        applies_to = [
            "Action::ec2:CreateNetworkInterface",
            "Action::ec2:DeleteNetworkInterface",
            "Action::ec2:DescribeNetworkInterfaces",
            "Resource::arn:aws:ec2:*:*:network-interface/*",
            f"Resource::arn:aws:logs:{region}:{account}:log-group:/aws/codebuild/{project_logical_id}:*",
            f"Resource::arn:aws:codebuild:{region}:{account}:report-group/{project_logical_id}-*",
        ]

        NagSuppressions.add_resource_suppressions(
            policy,
            [
                {
                    "id": "HIPAA.Security-IAMNoInlinePolicy",
                    "reason": "CDK-generated inline policy for CodeBuild role. Scope is limited and reviewed."
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "CodeBuild requires wildcard access to dynamic build report/log and network interface resources. These are ephemeral and isolated to the build context.",
                    "appliesTo": applies_to
                }
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Frontend CodeBuild project not found") from e


def _suppress_frontend_bucket_policy(stack: Stack, name: str):
    try:
        frontend = stack.node.find_child("Frontend")
        bucket = frontend.node.find_child(f"{name}-FrontendBucket")
        policy = bucket.policy

        NagSuppressions.add_resource_suppressions(
            policy,
            [
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
    except Exception as e:
        raise InapplicableSuppressionError("Frontend bucket policy not found") from e


def _suppress_log_bucket(stack: Stack, name: str):
    try:
        bucket = stack.node.find_child(f"{name}-LogBucket")
        NagSuppressions.add_resource_suppressions(
            bucket,
            [
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
                },
                {
                    "id": "AwsSolutions-S10",
                    "reason": "ALB access logs require a bucket without enforced aws:SecureTransport policies; encryption is still applied using S3-managed keys."
                }
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Log bucket not found") from e


def _suppress_backend_bucket(stack: Stack, name: str):
    try:
        backend = stack.node.find_child("Backend")
        bucket = backend.node.find_child(f"{name}-BackendStorage")
        NagSuppressions.add_resource_suppressions(
            bucket,
            [
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "Versioning is not required for backend data in this deployment"
                },
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "Data replication is handled externally or not required"
                }
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Backend storage bucket not found") from e


def _suppress_backend_iams(stack: Stack, name: str):
    from cdk_nag import NagSuppressions

    backend = stack.node.find_child("Backend")

    def scoped_iam5_suppressions(policy_node, applies_to: list[str], reason: str):
        NagSuppressions.add_resource_suppressions(
            policy_node,
            suppressions=[{
                "id": "AwsSolutions-IAM5",
                "reason": reason,
                "appliesTo": applies_to
            }]
        )

    wild_s3 = [
        "Action::s3:GetObject*",
        "Action::s3:GetBucket*",
        "Action::s3:List*",
        "Action::s3:DeleteObject*",
        "Action::s3:Abort*",
        f"Resource::arn:aws:s3:::{name}-BackendStorage/*"
    ]

    wild_kms = [
        "Action::kms:ReEncrypt*",
        "Action::kms:GenerateDataKey*"
    ]

    # Suppress IAM5 on all backend task roles
    service = backend.node.find_child(f"{name}-BackendService")
    roles_to_patch = [
        service.task_definition.task_role,
        backend.node.find_child(f"{name}-SetupDbTaskDef").task_role,
        backend.node.find_child(f"{name}-ValidationMonitorTaskDef").task_role,
    ]

    for role in roles_to_patch:
        default_policy = role.node.find_child("DefaultPolicy")
        scoped_iam5_suppressions(
            default_policy,
            wild_s3 + wild_kms,
            "Backend tasks require wildcard access for S3 media and KMS operations"
        )

    # Suppress on RunSetupTask custom resource
    run_setup = backend.node.find_child(f"{name}-RunSetupTask")
    cr_policy = run_setup.node.find_child("CustomResourcePolicy")
    scoped_iam5_suppressions(
        cr_policy,
        ["Resource::*"],
        "AwsCustomResource needs broad permissions to invoke ECS task"
    )

    # Suppress on EventsRole (CloudWatch Events rule to run validation task)
    events_role = backend.node.find_child(f"{name}-ValidationMonitorTaskDef").node.try_find_child("EventsRole")
    if events_role:
        default_policy = events_role.node.find_child("DefaultPolicy")
        scoped_iam5_suppressions(
            default_policy,
            [f"Resource::arn:aws:ecs:{stack.region}:*:task/{name}-Cluster/*"],
            "EventsRole requires wildcard task ARN to launch validation task"
        )


def _suppress_frontend_iam(stack: Stack, name: str):
    try:
        frontend = stack.node.find_child("Frontend")
        build = frontend.node.find_child(f"{name}-FrontendBuild")
        role = build.role
        default_policy = role.node.find_child("DefaultPolicy")
        policy_doc = build.node.find_child("PolicyDocument")  # enforce presence

        if policy_doc is None:
            raise ValueError("PolicyDocument missing on frontend CodeBuild project")

        frontend_bucket = frontend.node.find_child(f"{name}-FrontendBucket")
        frontend_bucket_logical_id = stack.get_logical_id(frontend_bucket.node.default_child)

        log_bucket = stack.node.find_child(f"{name}-LogBucket")
        log_bucket_logical_id = stack.get_logical_id(log_bucket.node.default_child)

        # Suppress wildcard IAM permissions
        NagSuppressions.add_resource_suppressions(
            default_policy,
            suppressions=[{
                "id": "AwsSolutions-IAM5",
                "reason": "CodeBuild requires wildcard access for artifacts, logs, and dynamic infrastructure",
                "appliesTo": [
                    f"Resource::<{frontend_bucket_logical_id}.Arn>/*",
                    f"Resource::<{log_bucket_logical_id}.Arn>/*",
                    "Action::s3:GetObject*",
                    "Action::s3:GetBucket*",
                    "Action::s3:List*",
                    "Action::s3:DeleteObject*",
                    "Action::s3:Abort*"
                ]
            }],
            apply_to_children=True
        )

        # Suppress inline policy warning
        NagSuppressions.add_resource_suppressions(
            policy_doc,
            suppressions=[{
                "id": "HIPAA.Security-IAMNoInlinePolicy",
                "reason": "CDK-generated inline policy for CodeBuild role with limited, reviewed scope"
            }],
            apply_to_children=True
        )

    except Exception as e:
        raise InapplicableSuppressionError("Failed to apply frontend IAM suppressions") from e


def _suppress_frontend_bucket(stack: Stack, name: str):
    try:
        frontend = stack.node.find_child("Frontend")
        bucket = frontend.node.find_child(f"{name}-FrontendBucket")

        # Suppress on the bucket itself for versioning/replication/KMS
        NagSuppressions.add_resource_suppressions(
            bucket,
            suppressions=[
                {
                    "id": "HIPAA.Security-S3BucketReplicationEnabled",
                    "reason": "Replication is not required for frontend static assets"
                },
                {
                    "id": "HIPAA.Security-S3BucketVersioningEnabled",
                    "reason": "Versioning is not required for static site bucket"
                },
                {
                    "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                    "reason": "S3-managed encryption is sufficient for public static assets"
                }
            ],
            apply_to_children=True
        )

        # Suppress S5 on the bucket policy *resource*
        NagSuppressions.add_resource_suppressions(
            bucket.node.default_child,
            suppressions=[{
                "id": "AwsSolutions-S5",
                "reason": "Access restricted via CloudFront Origin Access Control and deny non-SecureTransport policy"
            }]
        )

    except Exception as e:
        raise InapplicableSuppressionError("Failed to apply frontend bucket suppressions") from e


def _suppress_vpc_routes(stack: Stack, name: str):

    try:
        vpc = stack.node.find_child(f"{name}-Vpc")
        vpc_resource = vpc.node.default_child

        # Suppress default SG warning (we ensure it's unused)
        NagSuppressions.add_resource_suppressions(
            vpc_resource,
            suppressions=[{
                "id": "HIPAA.Security-VPCDefaultSecurityGroupClosed",
                "reason": "Default SG is never used; all resources are explicitly assigned secure SGs"
            }]
        )

        # Suppress IGW route warnings on public subnets (used by ALB only)
        for i in [1, 2]:
            try:
                subnet = vpc.node.find_child(f"publicSubnet{i}")
                default_route = subnet.node.find_child("DefaultRoute")
                NagSuppressions.add_resource_suppressions(
                    default_route,
                    suppressions=[{
                        "id": "HIPAA.Security-VPCNoUnrestrictedRouteToIGW",
                        "reason": "This route is required for ALB in public subnet"
                    }]
                )
            except Exception as e:
                raise InapplicableSuppressionError(f"Failed to suppress route on publicSubnet{i}") from e

    except Exception as e:
        raise InapplicableSuppressionError("Failed to apply VPC route suppressions") from e


def _suppress_secret_rotation(stack: Stack, name: str):
    reason = (
        "Automatic secret rotation is out of scope for this deployment due to operational and architectural "
        "constraints."
        "The RDS secret is rotated manually as needed, and the SMTP secret relies on IAM-auth credentials that do not "
        "support automated rotation via Secrets Manager. Risks are mitigated through limited access, audit logging, "
        "and enforced TLS in all secret usage contexts."
    )

    try:
        backend = stack.node.find_child("Backend")
        for suffix in ["DbSecret", "SmtpSecret"]:
            secret = backend.node.find_child(f"{name}-{suffix}")
            NagSuppressions.add_resource_suppressions(
                secret,
                [
                    {"id": "AwsSolutions-SMG4", "reason": reason},
                    {"id": "HIPAA.Security-SecretsManagerRotationEnabled", "reason": reason},
                    {"id": "HIPAA.Security-SecretsManagerUsingKMSKey", "reason": reason}
                ]
            )

        # Suppress secret attached to RDS instance
        db_instance = backend.node.find_child(f"{name}-BackendDatabase")
        rds_secret = db_instance.node.find_child("Secret")
        NagSuppressions.add_resource_suppressions(
            rds_secret,
            [
                {"id": "AwsSolutions-SMG4", "reason": reason},
                {"id": "HIPAA.Security-SecretsManagerRotationEnabled", "reason": reason},
                {"id": "HIPAA.Security-SecretsManagerUsingKMSKey", "reason": reason}
            ]
        )
    except Exception as e:
        raise InapplicableSuppressionError("Failed to suppress secret rotation findings") from e


def _suppress_ecs_env_vars(stack: Stack, name: str):
    reason = (
        "Environment variables are used for non-sensitive application configuration (e.g., log level, feature flags). "
        "Secrets and credentials are injected via Secrets Manager and not stored in plaintext. "
        "Splitting environment config across multiple mechanisms would increase complexity without improving security."
    )

    try:
        backend = stack.node.find_child("Backend")

        # 1. BackendService task definition (access via service object)
        service = backend.node.find_child(f"{name}-BackendService")
        NagSuppressions.add_resource_suppressions(
            service.task_definition,
            [{"id": "AwsSolutions-ECS2", "reason": reason}]
        )

        # 2. SetupDb task definition
        setup = backend.node.find_child(f"{name}-SetupDbTaskDef")
        NagSuppressions.add_resource_suppressions(
            setup,
            [{"id": "AwsSolutions-ECS2", "reason": reason}]
        )

        # 3. ValidationMonitor task definition
        monitor = backend.node.find_child(f"{name}-ValidationMonitorTaskDef")
        NagSuppressions.add_resource_suppressions(
            monitor,
            [{"id": "AwsSolutions-ECS2", "reason": reason}]
        )

    except Exception as e:
        raise InapplicableSuppressionError("Failed to suppress ECS env var warnings") from e


def _suppress_inline_iam_policies(stack: Stack, name: str):
    reason = (
        "CDK creates inline policies for task and execution roles to scope them tightly to the specific actions needed."
        "These policies are reviewed and minimally scoped, and refactoring them into standalone managed policies "
        "would reduce clarity"
        "without meaningful security benefit."
    )

    try:
        backend = stack.node.find_child("Backend")

        policies = [
            # Task roles
            backend.node.find_child(f"{name}-BackendService").task_definition.task_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-SetupDbTaskDef").task_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-ValidationMonitorTaskDef").task_role.node.find_child("DefaultPolicy"),

            # Execution roles
            backend.node.find_child(f"{name}-BackendService").task_definition.execution_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-SetupDbTaskDef").execution_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-ValidationMonitorTaskDef").execution_role.node.find_child("DefaultPolicy"),
        ]

        for policy in policies:
            NagSuppressions.add_resource_suppressions(
                policy,
                [{"id": "HIPAA.Security-IAMNoInlinePolicy", "reason": reason}]
            )

        try:
            events_role = backend.node.find_child(f"{name}-ValidationMonitorTaskDef").node.find_child("EventsRole").node.find_child("DefaultPolicy")
            if events_role is not None:
                NagSuppressions.add_resource_suppressions(
                    events_role,
                    [{"id": "HIPAA.Security-IAMNoInlinePolicy", "reason": reason}]
                )
        except RuntimeError:
            # EventsRole not found; ignore
            pass

        # Custom resource policy for the RunSetupTask
        run_setup = backend.node.find_child(f"{name}-RunSetupTask")
        policy_resource = run_setup.node.find_child("CustomResourcePolicy").node.find_child("Resource")
        NagSuppressions.add_resource_suppressions(
            policy_resource,
            [{"id": "HIPAA.Security-IAMNoInlinePolicy", "reason": reason}]
        )

    except Exception as e:
        raise InapplicableSuppressionError("Failed to suppress inline IAM policy warnings") from e


def _suppress_ecs_iam5_wildcards(stack: Stack, name: str):
    reason = (
        "Task roles require wildcard access to dynamic paths within the backend S3 bucket for runtime media storage. "
        "Access is scoped to a single known bucket, and permission actions are limited to read/write as required."
    )

    applies_to = [
        "Action::s3:GetObject*",
        "Action::s3:PutObject*",
        f"Resource::arn:aws:s3:::{name}-BackendStorage/*"
    ]

    try:
        backend = stack.node.find_child("Backend")

        task_defs = [
            backend.node.find_child(f"{name}-BackendService").task_definition.task_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-SetupDbTaskDef").task_role.node.find_child("DefaultPolicy"),
            backend.node.find_child(f"{name}-ValidationMonitorTaskDef").task_role.node.find_child("DefaultPolicy"),
        ]

        for policy in task_defs:
            NagSuppressions.add_resource_suppressions(
                policy,
                [
                    {
                        "id": "AwsSolutions-IAM5",
                        "reason": reason,
                        "appliesTo": applies_to
                    }
                ]
            )

    except Exception as e:
        raise InapplicableSuppressionError("Failed to suppress ECS IAM5 wildcard findings") from e
