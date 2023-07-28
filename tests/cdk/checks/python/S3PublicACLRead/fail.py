from constructs import Construct
from aws_cdk import App, Stack 
from aws_cdk import (
    aws_s3 as s3
)


class MyS3Stack(Stack):

    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        bucket = s3.Bucket(self, "MyPublicReadBucket",
                            bucket_name="my-public-read-bucket",  # replace with your desired bucket name
                            access_control=s3.BucketAccessControl.PUBLIC_READ
                            )
        
app = App()
MyS3Stack(app, "MyS3Stack")
app.synth()
