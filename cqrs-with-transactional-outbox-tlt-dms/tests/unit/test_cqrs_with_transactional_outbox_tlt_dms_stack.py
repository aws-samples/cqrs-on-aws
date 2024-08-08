import aws_cdk as core
import aws_cdk.assertions as assertions

from cqrs_with_transactional_outbox_tlt_dms.cqrs_with_transactional_outbox_tlt_dms_stack import CqrsWithTransactionalOutboxTltDmsStack

# example tests. To run these tests, uncomment this file along with the example
# resource in cqrs_with_transactional_outbox_tlt_dms/cqrs_with_transactional_outbox_tlt_dms_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = CqrsWithTransactionalOutboxTltDmsStack(app, "cqrs-with-transactional-outbox-tlt-dms")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
