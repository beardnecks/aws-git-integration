"""Creates a list of the public IPs for Bitbucket and Github

Fetches an updated list of Bitbucket and Github public server IPs
to be used for authenticating webhooks in the GitPull lambda function
"""

import os

import boto3
import requests


def lambda_handler(event: dict, context):
    """Creates a list of the public IPs for Bitbucket and Github


    After creating a comma separated list the function uploads the file
    to an S3 bucket for use by the GitPull lambda
    :param event: Lambda event information from AWS - Not used
    :param context: Lambda context information from AWS - Not used
    :return:
    """
    ip_bucket = os.environ["IPBucket"]

    # Bitbucket IPs
    resp = requests.get("https://ip-ranges.atlassian.com")
    bitbucket_resp = resp.json()

    valid_ips = ""
    for item in bitbucket_resp["items"]:
        valid_ips += item["cidr"] + ","

    # Github IPs
    resp = requests.get("https://api.github.com/meta")
    github_resp = resp.json()

    for ip in github_resp["web"]:
        valid_ips += ip + ","

    for ip in github_resp["api"]:
        valid_ips += ip + ","

    for ip in github_resp["git"]:
        valid_ips += ip + ","

    f = open("/tmp/ips", "wb")
    f.write(valid_ips.rstrip(",").encode())  # Strip to remove trailing comma
    f.close()
    s3 = boto3.client("s3")
    s3.upload_file("/tmp/ips", ip_bucket, "ips")
    print("Updated valid ips")
