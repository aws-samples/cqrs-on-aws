import aws_cdk as cdk

from vpc_stack import VpcStack

vpc_app = cdk.App()
stack = VpcStack(vpc_app, "cqrsOnAws")
vpc_app.synth()