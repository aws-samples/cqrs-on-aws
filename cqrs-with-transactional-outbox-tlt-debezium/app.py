
import aws_cdk as cdk

from vpc_stack import VpcStack
import os

vpc_app = cdk.App()
VpcStack(vpc_app, "cqrsOnAws")

vpc_app.synth()
