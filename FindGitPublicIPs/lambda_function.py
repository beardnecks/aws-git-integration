import boto3
import requests


def lambda_handler(event: dict, context):
    # Bitbucket IPs
    resp = requests.get("https://ip-ranges.atlassian.com")
    bitbucket_resp = resp.json()

    valid_ips = ""
    for item in bitbucket_resp["items"]:
        valid_ips = valid_ips + "," + item

    # Github IPs
    resp = requests.get("https://api.github.com/meta")
    github_resp = resp.json()

    for ip in github_resp["hooks"]:
        valid_ips = valid_ips + "," + ip

    for ip in github_resp["web"]:
        valid_ips = valid_ips + "," + ip

    for ip in github_resp["api"]:
        valid_ips = valid_ips + "," + ip

    for ip in github_resp["git"]:
        valid_ips = valid_ips + "," + ip

    for ip in github_resp["pages"]:
        valid_ips = valid_ips + "," + ip

    for ip in github_resp["importer"]:
        valid_ips = valid_ips + "," + ip

    f = open("/tmp/ips", "wb")
    f.write(valid_ips)
    f.close()
    s3 = boto3.client("s3")
    s3.upload_file("/tmp/ips", event["ResourceProperties"]["IPBucket"], "ips")
    print("Updated valid ips")
