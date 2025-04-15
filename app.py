#!/usr/bin/env python3
# Horrible Hack to support NVM
from cert_stack import CertificateStack
from nag_supressions import suppress_nags_post_synth
from tests.unit import _nvm_hack

_nvm_hack.hack_nvm_path()
# /HH

from aws_cdk import App, Aspects
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
import argparse
import json
from pathlib import Path
from galv_cdk.galv_stack import GalvStack
from utils import print_nag_findings

# Parse command-line arguments
parser = argparse.ArgumentParser()
parser.add_argument("--context", type=str, help="Path to cdk.json")
args = parser.parse_args()

# Load context from cdk.json if provided
if args.context:
    context_path = Path(args.context)
else:
    context_path = Path("cdk.json")
context = json.loads(context_path.read_text())["context"]

app = App(context=context)

# Create the CDK app with the loaded context
is_route_53_domain = context.get("isRoute53Domain", True)
if not context.get("isRoute53Domain"):
    cert_stack = CertificateStack(
        app,
        "CertStack",
        domain_name=context["domainName"],
        subdomain=context["frontendSubdomain"],
        hosted_zone_id=context["hostedZoneId"]
    )
    certificate_arn = cert_stack.certificate.certificate_arn
else:
    certificate_arn = None

# Instantiate the stack
stack = GalvStack(app, "GalvStack", certificate_arn=certificate_arn)

# Add CDK Nag rules
Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
Aspects.of(app).add(HIPAASecurityChecks())

app.synth()

# Disable specific CDK Nag rules
suppress_nags_post_synth(stack, stack.name)

print_nag_findings(stack)