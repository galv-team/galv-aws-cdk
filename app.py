#!/usr/bin/env python3
import aws_cdk as cdk
from galv_cdk.galv_stack import GalvStack

app = cdk.App()
GalvStack(app, "GalvStack")
app.synth()
