"""Empty buckets on received CloudFormation delete event

Deletes contents of KeyBucket, IPBucket and SourceBucket when the
CloudFormation template gets deleted. This allows CloudFormation
to delete the mentioned buckets without issue, as a bucket with
contents can not be deleted by CloudFormation
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


def lambda_handler(event, context):
    """

    :param event: Lambda event information from AWS
    :param context: Lambda context information from AWS
    :return:
    """
    try:
        if event["RequestType"] == "Delete":
            s3 = boto3.client("s3")
            # Delete KeyBucket contents
            print()
            "Getting KeyBucket objects..."
            s3objects = s3.list_objects_v2(
                Bucket=event["ResourceProperties"]["KeyBucket"]
            )
            if "Contents" in list(s3objects.keys()):
                print()
                "Deleting KeyBucket objects %s..." % str(
                    [{"Key": key["Key"]} for key in s3objects["Contents"]]
                )
                s3.delete_objects(
                    Bucket=event["ResourceProperties"]["KeyBucket"],
                    Delete={
                        "Objects": [
                            {"Key": key["Key"]} for key in s3objects["Contents"]
                        ]
                    },
                )
            # Delete IPBucket contents
            print()
            print(event["ResourceProperties"])
            try:
                "Getting KeyBucket objects..."
                s3objects = s3.list_objects_v2(
                    Bucket=event["ResourceProperties"]["IPBucket"]
                )
                if "Contents" in list(s3objects.keys()):
                    print()
                    "Deleting IPBucket objects %s..." % str(
                        [{"Key": key["Key"]} for key in s3objects["Contents"]]
                    )
                    s3.delete_objects(
                        Bucket=event["ResourceProperties"]["IPBucket"],
                        Delete={
                            "Objects": [
                                {"Key": key["Key"]} for key in s3objects["Contents"]
                            ]
                        },
                    )
            except Exception as e:
                print(e)

            # Delete Source bucket contents and versions
            print()
            "Getting SourceBucket objects..."
            objects = []
            versions = s3.list_object_versions(
                Bucket=event["ResourceProperties"]["SourceBucket"]
            )
            while versions:
                if "Versions" in list(versions.keys()):
                    for v in versions["Versions"]:
                        objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                if "DeleteMarkers" in list(versions.keys()):
                    for v in versions["DeleteMarkers"]:
                        objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
                if versions["IsTruncated"]:
                    versions = s3.list_object_versions(
                        Bucket=event["ResourceProperties"]["SourceBucket"],
                        VersionIdMarker=versions["NextVersionIdMarker"],
                    )
                else:
                    versions = False
            if objects:
                s3.delete_objects(
                    Bucket=event["ResourceProperties"]["SourceBucket"],
                    Delete={"Objects": objects},
                )
        send(event, context, SUCCESS, {}, "")
    except Exception as e:
        print()
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
