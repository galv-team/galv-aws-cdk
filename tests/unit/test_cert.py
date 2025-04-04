# Horrible Hack to support NVM
import _nvm_hack
_nvm_hack.hack_nvm_path()
# /HH

import unittest

from aws_cdk import App
from aws_cdk.assertions import Template, Match
from galv_cdk.cert_stack import CertificateStack
from cdk_nag import AwsSolutionsChecks
from aws_cdk import Aspects


class TestCertStack(unittest.TestCase):
    def test_cert_stack(self):
        app = App(context={
            "domainName": "example.com",
            "frontendSubdomain": "www",
            "hostedZoneId": "Z1PA6795UKMFR9"
        })

        stack = CertificateStack(
            app,
            "TestCertStack",
            domain_name=app.node.try_get_context("domainName"),
            subdomain=app.node.try_get_context("frontendSubdomain"),
            hosted_zone_id=app.node.try_get_context("hostedZoneId"),
        )

        Aspects.of(stack).add(AwsSolutionsChecks(verbose=True))
        template = Template.from_stack(stack)

        template.resource_count_is("AWS::CertificateManager::Certificate", 1)
        template.has_resource_properties("AWS::CertificateManager::Certificate", {
            "DomainName": Match.string_like_regexp("www.example.com"),
            "ValidationMethod": "DNS"
        })


if __name__ == "__main__":
    unittest.main()