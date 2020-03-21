"""Generate rsa key-pair on CFN create event

The function generates a 2048 bit RSA key-pair upon a CFN create request.
It then returns the public key, to be used as the physical ID of a
CloudFormation custom resource, while the private key is encrypted
using KMS, and uploaded to a specified S3 bucket.

"""

#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

import json
import traceback

import boto3
import requests
from cryptography.hazmat.backends import \
    default_backend as crypto_default_backend
from cryptography.hazmat.primitives import \
    serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def lambda_handler(event, context):
    try:
        if event["RequestType"] == "Create":
            # Generate keys
            new_key = rsa.generate_private_key(
                backend=crypto_default_backend(), public_exponent=65537, key_size=2048
            )
            priv_key = new_key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption(),
            )
            pub_key = (
                new_key.public_key()
                .public_bytes(
                    crypto_serialization.Encoding.OpenSSH,
                    crypto_serialization.PublicFormat.OpenSSH,
                )
                .decode("utf-8")
            )
            # Encrypt private key
            kms = boto3.client("kms", region_name=event["ResourceProperties"]["Region"])
            enc_key = kms.encrypt(
                KeyId=event["ResourceProperties"]["KMSKey"], Plaintext=priv_key
            )["CiphertextBlob"]
            f = open("/tmp/enc_key", "wb")
            f.write(enc_key)
            f.close()
            # Upload private key to S3
            s3 = boto3.client("s3")
            s3.upload_file(
                "/tmp/enc_key", event["ResourceProperties"]["KeyBucket"], "enc_key"
            )
        else:
            pub_key = event["PhysicalResourceId"]
        send(event, context, SUCCESS, {}, pub_key)
    except Exception as e:
        traceback.print_exc()
        send(event, context, FAILED, {}, "")


SUCCESS = "SUCCESS"
FAILED = "FAILED"


def send(
    event,
    context,
    response_status,
    response_data,
    physical_resource_id=None,
    no_echo=False,
):
    """Send CloudFormation Custom Resource Response

    :param event: Lambda provided event
    :param context: Lambda provided context
    :param response_status: The status value sent by the custom resource provider in response to
            an AWS CloudFormation-generated request.
            (SUCCESS or FAILURE)
    :param response_data: Data in body of request
    :param physical_resource_id: This value should be an identifier unique to the custom resource vendor,
        and can be up to 1 Kb in size. The value must be a non-empty string and must be identical for all
        responses for the same resource.
    :param no_echo: Optional. Indicates whether to mask the output of the custom resource when retrieved
            by using the Fn::GetAtt function. If set to true, all returned values are masked with
            asterisks (*****).
            The default value is false.
    """
    response_url = event["ResponseURL"]

    response_body = {
        "Status": response_status,
        "Reason": "See the details in CloudWatch Log Stream: "
        + context.log_stream_name,
        "PhysicalResourceId": physical_resource_id or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "NoEcho": no_echo,
        "Data": response_data,
    }

    json_response_body = json.dumps(response_body)

    headers = {"content-type": "", "content-length": str(len(json_response_body))}

    try:
        response = requests.put(response_url, data=json_response_body, headers=headers)
        print("Status code: " + response.reason)
    except Exception as e:
        print("send(..) failed executing requests.put(..): " + str(e))
