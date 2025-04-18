from aws_cdk import Stack
from cdk_nag import NagSuppressions


class InapplicableSuppressionError(Exception):
    pass


def suppress_nags_pre_synth(stack: Stack):
    name = stack.name

    try:
        if not stack.node.try_get_context("isRoute53Domain"):
            _suppress_cert_stack(stack)

        _suppress_frontend(stack, name)
        _suppress_backend_taskrole_policy(stack, name)
        _suppress_vpc_endpoints(stack, name)
        _suppress_frontend_bucket_policy(stack, name)
        _suppress_log_bucket(stack, name)
        _suppress_backend_bucket(stack, name)
        _suppress_backend_iams(stack, name)
        _suppress_secret_rotation(stack, name)
        _suppress_ecs_env_vars(stack, name)
        _suppress_inline_iam_policies(stack, name)
        _suppress_ecs_iam5_wildcards(stack, name)
        _suppress_codebuild_kms(stack, name)
        _suppress_log_bucket_pre(stack, name)
        _suppress_vpc_routes_pre(stack, name)
        _suppress_frontend_bucket(stack, name)
        _suppress_frontend_iam(stack, name)
        _suppress_lambda_iam4(stack)
        _suppress_backend_alb_sg(stack, name)
        _suppress_db_sg_validation_failures(stack, name)
        _suppress_db_indirect_ingress_validation(stack, name)
        _suppress_rds_nags(stack, name)
        _suppress_alb_attributes(stack, name)
        _suppress_lambda_resource(stack)
    except Exception as e:
        raise InapplicableSuppressionError("Failed to apply pre-synth suppressions") from e


def suppress_nags_post_synth(stack: Stack, name: str):
    """
    Apply centralized CDK Nag suppressions to known resources based on {name}.
    This should be called after all constructs are created.
    """
    try:
        pass
    except Exception as e:
        raise InapplicableSuppressionError("Failed to apply frontend bucket post-synth suppressions") from e


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
    frontend = stack.node.find_child("Frontend")
    cdn = frontend.node.find_child(f"{name}-FrontendCDN")
    NagSuppressions.add_resource_suppressions(
        cdn.node.default_child,
        [{
            "id": "AwsSolutions-CFR1",
            "reason": "Geo restrictions are not required for this public static site."
        }]
    )


def _suppress_backend_taskrole_policy(stack: Stack, name: str):
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


def _suppress_vpc_endpoints(stack: Stack, name: str):
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


def _suppress_frontend_bucket_policy(stack: Stack, name: str):
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


def _suppress_log_bucket(stack: Stack, name: str):
    bucket = stack.node.find_child(f"{name}-LogBucket")
    NagSuppressions.add_resource_suppressions(
        bucket,
        [
            {
                "id": "AwsSolutions-S10",
                "reason": "ALB access logs require a bucket without enforced aws:SecureTransport policies; encryption is still applied using S3-managed keys."
            }
        ]
    )


def _suppress_log_bucket_pre(stack: Stack, name: str):
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
        ]
    )
    NagSuppressions.add_resource_suppressions(
        bucket.node.default_child,
        [
            {
                "id": "HIPAA.Security-S3DefaultEncryptionKMS",
                "reason": "ALB access logs cannot be delivered to a KMS-encrypted bucket; S3-managed encryption is used instead."
            },
        ]
    )


def _suppress_backend_bucket(stack: Stack, name: str):
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


def _suppress_backend_iams(stack: Stack, name: str):
    backend = stack.node.find_child("Backend")
    region = stack.region
    account = stack.account

    bucket = backend.node.find_child(f"{name}-BackendStorage")
    bucket_arn_ref = f"Resource::<{stack.get_logical_id(bucket.node.default_child)}.Arn>/*"

    base_applies_to = [
        "Action::s3:GetObject*",
        "Action::s3:GetBucket*",
        "Action::s3:List*",
        "Action::s3:DeleteObject*",
        "Action::s3:Abort*",
        "Action::kms:ReEncrypt*",
        "Action::kms:GenerateDataKey*",
        bucket_arn_ref
    ]

    task_defs = [
        backend.node.find_child(f"{name}-BackendService").task_definition,
        backend.node.find_child(f"{name}-SetupDbTaskDef"),
        backend.node.find_child(f"{name}-ValidationMonitorTaskDef"),
    ]

    for task_def in task_defs:
        default_policy = task_def.task_role.node.find_child("DefaultPolicy")
        NagSuppressions.add_resource_suppressions(
            default_policy.node.default_child,
            suppressions=[{
                "id": "AwsSolutions-IAM5",
                "reason": "Wildcard permissions required for backend tasks using S3 and KMS",
                "appliesTo": base_applies_to
            }]
        )

    # Custom resource: RunSetupTask
    run_setup = backend.node.find_child(f"{name}-RunSetupTask")
    cr_policy = run_setup.node.find_child("CustomResourcePolicy")
    NagSuppressions.add_resource_suppressions(
        cr_policy,
        suppressions=[{
            "id": "AwsSolutions-IAM5",
            "reason": "Custom resource requires wildcard ECS task invocation",
            "appliesTo": ["Resource::*"]
        }]
    )

    # Events rule for validation task
    events_role = backend.node.find_child(f"{name}-ValidationMonitorTaskDef").node.try_find_child("EventsRole")
    if events_role:
        default_policy = events_role.node.find_child("DefaultPolicy")
        cluster = backend.node.find_child(f"{name}-Cluster")
        cluster_logical_id = stack.get_logical_id(cluster.node.default_child)

        NagSuppressions.add_resource_suppressions(
            default_policy.node.default_child,
            suppressions=[{
                "id": "AwsSolutions-IAM5",
                "reason": "EventsRole requires wildcard access to task ARNs",
                "appliesTo": [f"Resource::arn:<AWS::Partition>:ecs:{region}:*:task/<{cluster_logical_id}>/*"]
            }]
        )


def _suppress_frontend_iam(stack: Stack, name: str):
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

    partition = "aws"  # fine unless using multiple partitions (e.g. AWS GovCloud or China).
    region = stack.region
    account = stack.account

    applies_to = [
        "Action::s3:GetObject*",
        "Action::s3:GetBucket*",
        "Action::s3:List*",
        "Action::s3:DeleteObject*",
        "Action::s3:Abort*",
        f"Resource::<{frontend_bucket_logical_id}.Arn>/*",
        f"Resource::<{log_bucket_logical_id}.Arn>/*",
        "Action::ec2:CreateNetworkInterface",
        "Action::ec2:DeleteNetworkInterface",
        "Action::ec2:DescribeNetworkInterfaces",
        f"Resource::arn:{partition}:ec2:{region}:{account}:network-interface/*",
        f"Resource::arn:{partition}:logs:{region}:{account}:log-group:/aws/codebuild/{stack.get_logical_id(build.node.default_child)}:*",
        f"Resource::arn:{partition}:codebuild:{region}:{account}:report-group/{stack.get_logical_id(build.node.default_child)}-*",
    ]

    # Suppress wildcard IAM permissions
    NagSuppressions.add_resource_suppressions(
        default_policy.node.default_child,
        suppressions=[
            {
                "id": "AwsSolutions-IAM5",
                "reason": "CodeBuild requires wildcard access for artifacts, logs, network interfaces, and dynamic infrastructure",
                "appliesTo": applies_to
            },
            {
                "id": "HIPAA.Security-IAMNoInlinePolicy",
                "reason": "CodeBuild role uses inline policy generated by CDK with tightly scoped permissions"
            }
        ]
    )

    # Nag does not evaluate the resource ARN correctly, so we need to add a wildcard suppression
    NagSuppressions.add_resource_suppressions(
        default_policy.node.default_child,
        suppressions=[
            {
                "id": "AwsSolutions-IAM5",
                "reason": "Parent rule suppression for wildcard actions required by CodeBuild"
            }
        ]
    )

    # Suppress inline policy warning
    NagSuppressions.add_resource_suppressions(
        policy_doc.node.default_child,
        suppressions=[
            {
                "id": "HIPAA.Security-IAMNoInlinePolicy",
                "reason": "CDK-generated inline policy for CodeBuild role with limited, reviewed scope"
            },
            {
                "id": "AwsSolutions-IAM5",
                "reason": "CDK uses PolicyDocument with scoped wildcards for CodeBuild role",
                "appliesTo": ["Resource::*"]
            }
        ],
        apply_to_children=True
    )

    NagSuppressions.add_resource_suppressions(
        build.node.default_child,
        [{
            "id": "HIPAA.Security-CodeBuildProjectSourceRepoUrl",
            "reason": "Public GitHub repo does not require OAuth; access is read-only and verified by branch ref"
        }]
    )


def _suppress_frontend_bucket(stack: Stack, name: str):
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
        }],
        apply_to_children=True
    )


def _suppress_vpc_routes_pre(stack: Stack, name: str):
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
        subnet = vpc.node.find_child(f"publicSubnet{i}")
        default_route = subnet.node.find_child("DefaultRoute")
        l1_route = getattr(default_route.node, "default_child", None) or default_route
        NagSuppressions.add_resource_suppressions(
            l1_route,
            suppressions=[{
                "id": "HIPAA.Security-VPCNoUnrestrictedRouteToIGW",
                "reason": "This route is required for ALB in public subnet"
            }]
        )


def _suppress_secret_rotation(stack: Stack, name: str):
    reason = (
        "Automatic secret rotation is out of scope for this deployment due to operational and architectural "
        "constraints."
        "The RDS secret is rotated manually as needed, and the SMTP secret relies on IAM-auth credentials that do not "
        "support automated rotation via Secrets Manager. Risks are mitigated through limited access, audit logging, "
        "and enforced TLS in all secret usage contexts."
    )

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


def _suppress_ecs_env_vars(stack: Stack, name: str):
    reason = (
        "Environment variables are used for non-sensitive application configuration (e.g., log level, feature flags). "
        "Secrets and credentials are injected via Secrets Manager and not stored in plaintext. "
        "Splitting environment config across multiple mechanisms would increase complexity without improving security."
    )

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


def _suppress_inline_iam_policies(stack: Stack, name: str):
    reason = (
        "CDK creates inline policies for task and execution roles to scope them tightly to the specific actions needed."
        "These policies are reviewed and minimally scoped, and refactoring them into standalone managed policies "
        "would reduce clarity"
        "without meaningful security benefit."
    )

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


def _suppress_codebuild_kms(stack: Stack, name: str):
    frontend = stack.node.find_child("Frontend")
    build = frontend.node.find_child(f"{name}-FrontendBuild")
    l1 = build.node.default_child  # <- This is the real target CDK Nag evaluates for suppressions

    NagSuppressions.add_resource_suppressions(
        l1,
        suppressions=[{
            "id": "AwsSolutions-CB4",
            "reason": "Build logs do not contain sensitive information and are stored in a private bucket using S3-managed encryption."
        }]
    )


def _suppress_lambda_iam4(stack: Stack):
    lambda_cr = stack.node.find_child("AWS679f53fac002430cb0da5b7982bd2287")
    role = lambda_cr.node.find_child("ServiceRole")
    l1_policy = role.node.default_child

    NagSuppressions.add_resource_suppressions(
        l1_policy,
        suppressions=[{
            "id": "AwsSolutions-IAM4",
            "reason": "CDK default Lambda uses managed policy for basic logging; not replaced to preserve default behavior",
            "appliesTo": [
                "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ]
        }]
    )


def _suppress_backend_alb_sg(stack: Stack, name: str):
    backend = stack.node.find_child("Backend")
    alb_sg = backend.node.find_child(f"{name}-ALBSG")
    lb_sg = backend.node.find_child(f"{name}-BackendService").load_balancer.connections.security_groups[0]  # Usually the same as alb_sg

    for sg in [alb_sg, lb_sg]:
        NagSuppressions.add_resource_suppressions(
            sg.node.default_child,
            [{
                "id": "AwsSolutions-EC23",
                "reason": "Ingress is restricted to HTTPS (port 443) for public access via ALB"
            }]
        )


def _suppress_db_sg_validation_failures(stack: Stack, name: str):
    """
    CdkNagValidationFailure[...] warnings come from CDK Nag being unable to evaluate certain SecurityGroupIngress rules
     due to intrinsic functions—like dynamic references to security group IDs or ports.
    """
    backend = stack.node.find_child("Backend")
    db_sg = backend.node.find_child(f"{name}-DBSG")
    NagSuppressions.add_resource_suppressions(
        db_sg.node.default_child,
        [
            {
                "id": "CdkNagValidationFailure",
                "reason": "Validation failure due to unresolved construct references in ingress rules; safe internal access only",
                "appliesTo": [
                    "HIPAA.Security-EC2RestrictedCommonPorts",
                    "HIPAA.Security-EC2RestrictedSSH"
                ]
            }
        ],
        apply_to_children=True
    )


def _suppress_db_indirect_ingress_validation(stack: Stack, name: str):
    backend = stack.node.find_child("Backend")
    db_sg = backend.node.find_child(f"{name}-DBSG")

    for child in db_sg.node.children:
        if ":{IndirectPort}" in child.node.path:
            NagSuppressions.add_resource_suppressions(
                child,
                [
                    {
                        "id": "CdkNagValidationFailure",
                        "reason": "CDK Nag cannot evaluate ingress rule with intrinsic target SG/port",
                        "appliesTo": [
                            "HIPAA.Security-EC2RestrictedCommonPorts",
                            "HIPAA.Security-EC2RestrictedSSH"
                        ]
                    }
                ]
            )


def _suppress_rds_nags(stack: Stack, name: str):
    backend = stack.node.find_child("Backend")
    db_instance = backend.node.find_child(f"{name}-BackendDatabase")

    NagSuppressions.add_resource_suppressions(
        db_instance.node.default_child,
        [
            {
                "id": "AwsSolutions-RDS3",
                "reason": "Multi-AZ is not enabled due to cost; availability tradeoff is accepted for this deployment"
            },
            {
                "id": "HIPAA.Security-RDSMultiAZSupport",
                "reason": "High availability is handled via backups and redeployment; Multi-AZ is not used"
            },
            {
                "id": "AwsSolutions-RDS11",
                "reason": "Using default Postgres port 5432; obscurity adds no meaningful security benefit"
            },
            {
                "id": "HIPAA.Security-RDSEnhancedMonitoringEnabled",
                "reason": "OS-level metrics are not required; CloudWatch and application-level monitoring are sufficient"
            },
            {
                "id": "HIPAA.Security-RDSInBackupPlan",
                "reason": "Automated backups and snapshot retention provide sufficient resilience; not using AWS Backup plan"
            },
            {
                "id": "HIPAA.Security-RDSLoggingEnabled",
                "reason": "Postgres logs are not exported to CloudWatch to minimize cost; app-layer logging is sufficient",
                "appliesTo": [
                    "LogExport::postgresql",
                    "LogExport::upgrade"
                ]
            }
        ]
    )


def _suppress_alb_attributes(stack: Stack, name: str):
    backend = stack.node.find_child("Backend")
    alb = backend.node.find_child(f"{name}-BackendService").load_balancer.node.default_child  # CfnLoadBalancer

    NagSuppressions.add_resource_suppressions(
        alb,
        [
            {
                "id": "HIPAA.Security-ALBHttpDropInvalidHeaderEnabled",
                "reason": "DropInvalidHeaderFields is explicitly enabled via LoadBalancerAttributes override"
            },
            {
                "id": "HIPAA.Security-ELBDeletionProtectionEnabled",
                "reason": "Deletion protection is enabled via LoadBalancerAttributes override"
            }
        ]
    )


def _suppress_lambda_resource(stack: Stack):
    lambda_cr = stack.node.find_child("AWS679f53fac002430cb0da5b7982bd2287")
    NagSuppressions.add_resource_suppressions(
        lambda_cr.node.default_child,
        [
            {
                "id": "AwsSolutions-L1",
                "reason": "CDK-generated custom resource Lambda; runtime control is not available"
            },
            {
                "id": "HIPAA.Security-LambdaConcurrency",
                "reason": "Concurrency limits not required for CDK custom resource"
            },
            {
                "id": "HIPAA.Security-LambdaDLQ",
                "reason": "DLQ not needed for fire-and-forget CDK custom resource"
            },
            {
                "id": "HIPAA.Security-LambdaInsideVPC",
                "reason": "This Lambda does not access VPC resources"
            }
        ]
    )
