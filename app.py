#!/usr/bin/env python3
# Horrible Hack to support NVM
import os
from tests.unit import _nvm_hack

_nvm_hack.hack_nvm_path()
# /HH

from frontend_stack import GalvFrontend

from aws_cdk import App, Aspects
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
import argparse
import json
from pathlib import Path
from galv_cdk.galv_stack import GalvBackend
from galv_cdk.nag_supressions import suppress_nags_post_synth
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

account = os.environ.get("CDK_DEFAULT_ACCOUNT")
region = os.environ.get("CDK_DEFAULT_REGION")

name = app.node.try_get_context("name") or "galv"

frontend = GalvFrontend(app, f"{name}-FrontendWafStack", name=name, certificate_arn=context.get("certificate_arn", None))

# Instantiate the stack
backend = GalvBackend(app, f"{name}-GalvStack", certificate_arn=context.get("certificate_arn", None), env={"account": account, "region": region})

# Add CDK Nag rules
Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
Aspects.of(app).add(HIPAASecurityChecks())

app.synth()

# Disable specific CDK Nag rules
suppress_nags_post_synth(frontend, frontend.name)
suppress_nags_post_synth(backend, backend.name)

print_nag_findings(frontend)
print_nag_findings(backend)