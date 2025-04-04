
from aws_cdk import (
    Stack,
    Environment,
    aws_certificatemanager as acm,
    aws_route53 as route53, CfnOutput, Fn,
)
from constructs import Construct
from cdk_nag import NagSuppressions


class CertificateStack(Stack):
    """
    When using non-Route53 DNS providers, you must create the certificate in the us-east-1 region.
    This is a hard requirement for ACM certificates used with CloudFront.
    """
    def __init__(self, scope: Construct, id: str, *, domain_name: str, subdomain: str, hosted_zone_id: str) -> None:
        super().__init__(scope, id, env=Environment(region="us-east-1"))

        fqdn = f"{subdomain}.{domain_name}".lstrip(".")

        zone = route53.HostedZone.from_hosted_zone_attributes(
            self,
            "Zone",
            hosted_zone_id=hosted_zone_id,
            zone_name=domain_name
        )

        cert = acm.CfnCertificate(
            self,
            "Certificate",
            domain_name=fqdn,
            validation_method="DNS",
        )

        NagSuppressions.add_resource_suppressions(
            cert,
            suppressions=[{
                "id": "AwsSolutions-ACM1",
                "reason": "Certificate is DNS validated."
            }]
        )

        self.certificate = cert

        # Output the validation CNAMEs
        CfnOutput(
            self,
            "DomainName",
            value=cert.domain_name,
            description="Domain name for which this certificate was requested."
        )

        CfnOutput(
            self,
            "FrontendCertValidationInfo",
            value=Fn.get_att("FrontendCertificate", "DomainValidationOptions").to_string(),
            description="CNAME validation info — check CloudFormation outputs or Certificate Manager console"
        )
