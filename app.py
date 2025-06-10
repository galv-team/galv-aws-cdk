#!/usr/bin/env python3
# Horrible Hack to support NVM
import os
from tests.unit import _nvm_hack

_nvm_hack.hack_nvm_path()
# /HH

from aws_cdk import App, Aspects
from cdk_nag import AwsSolutionsChecks, HIPAASecurityChecks
import argparse
import json
from pathlib import Path

from galv_cdk.log_bucket_stack import LogBucketStack
from galv_cdk.frontend_stack import GalvFrontend
from galv_cdk.backend_stack import GalvBackend
from galv_cdk.nag_suppressions import suppress_nags_post_synth
from galv_cdk.utils import print_nag_findings

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

account = os.environ.get("CDK_DEFAULT_ACCOUNT")
region = os.environ.get("CDK_DEFAULT_REGION")

app = App(context=context)

name = app.node.try_get_context("name") or "galv"
is_production = app.node.try_get_context("isProduction")
if is_production is None:
    is_production = True

log_bucket_stack = LogBucketStack(
    app,
    f"{name}-LogBucketStack",
    name=name,
    is_production=is_production,
    env={"account": account, "region": region},
)

# Instantiate the stack
backend = GalvBackend(
    app,
    f"{name}-BackendStack",
    log_bucket=log_bucket_stack.log_bucket,
    certificate_arn=context.get("certificate_arn", None),
    env={"account": account, "region": region},
)

frontend = GalvFrontend(
    app,
    f"{name}-FrontendStack",
    log_bucket=log_bucket_stack.log_bucket,
    certificate_arn=context.get("certificate_arn", None),
    backend_fqdn=backend.fqdn,
    env={"account": account, "region": region},
)

Aspects.of(app).add(AwsSolutionsChecks(verbose=True))
Aspects.of(app).add(HIPAASecurityChecks())

app.synth()

# Disable specific CDK Nag rules
suppress_nags_post_synth(frontend, frontend.name)
suppress_nags_post_synth(backend, backend.name)

print_nag_findings(frontend)
print_nag_findings(backend)
