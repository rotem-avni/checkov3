from constructs import Construct
from aws_cdk import (
    App, 
    Stack,
    aws_sns as sns,
    aws_kms as kms
)


class MyStack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Create a KMS key
        key = kms.Key(self, "MyKey")

        # Create an SNS Topic with the KMS key
        topic = sns.Topic(self, "Topic",
                          topic_name="my-topic",
                          master_key=key)

app = App()
MyStack(app, "MyStack")
app.synth()

