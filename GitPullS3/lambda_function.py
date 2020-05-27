"""Takes a webhook request from API gateway and clones a repository to an S3 bucket

A AWS lambda function that is triggered by a API gateway endpoint. It clones a repository
from either Bitbucket Cloud or from Github and creates a zip file that is uploaded to
a specified S3 bucket for consumption by e.g a CodePipeline pipeline.
"""

#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.
import base64
import distutils.util
import hashlib
import hmac
import json
import logging
import os

# Regex
import re
import shutil
import stat
from ipaddress import ip_address, ip_network
from zipfile import ZipFile

from boto3 import client
from git import Repo, exc

# If true the function will not include .git folder in the zip
exclude_git = bool(distutils.util.strtobool(os.environ["ExcludeGit"]))
ip_bucket = os.environ["IPBucket"]  # Name of bucket containing list of valid source IPs
ip_lambda = os.environ[
    "IPLambda"
]  # Name of lambda function to create list of source IPs

key = "enc_key"  # Name of private key file

# Configure logger. Change level from logger.ERROR to obtain more information in run logs
logger = logging.getLogger()
logger.setLevel(logging.ERROR)
logger.handlers[0].setFormatter(
    logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
)
logging.getLogger("boto3").setLevel(logging.ERROR)
logging.getLogger("botocore").setLevel(logging.ERROR)

s3 = client("s3")
kms = client("kms")


def write_key(filename: str, contents: bytes):
    """Writes contents to a given filename in /tmp

    :param filename: Name of file to write to /tmp/{filename}
    :param contents: Byte contents of the file to write
    """

    logger.info("Writing keys to /tmp/...")
    mode = stat.S_IRUSR | stat.S_IWUSR
    umask_original = os.umask(0)
    try:
        handle = os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, mode), "wb")
        handle.write(contents + b"\n")
        handle.close()
    except Exception as e:
        logger.error(
            "There was an error opening /tmp/%s for writing: %s" % (filename, e)
        )
    finally:
        os.umask(umask_original)


def get_keys(key_bucket: str, pubkey: str, update: bool = False):
    """Fetch RSA keys from a given S3 bucket

    Fetches private key from given key_bucket and decrypts using a key from KMS.
    Finally writes the key-pair to /tmp
    :param key_bucket: Name of bucket where private key is stored
    :param pubkey: Public RSA key as a string
    :param update: Run function, even if key files already exist
    """

    if (
        not os.path.isfile("/tmp/id_rsa")
        or not os.path.isfile("/tmp/id_rsa.pub")
        or update
    ):
        logger.info("Keys not found on Lambda container, fetching from S3...")
        enckey = s3.get_object(Bucket=key_bucket, Key=key)["Body"].read()
        privkey = kms.decrypt(CiphertextBlob=enckey)["Plaintext"]
        write_key("/tmp/id_rsa", privkey)
        write_key("/tmp/id_rsa.pub", str.encode(pubkey))


def invoke_ip_lambda():
    lambda_client = client("lambda")
    lambda_client.invoke(
        FunctionName=ip_lambda, InvocationType="RequestResponse", Payload=b"{}"
    )


def get_ips(override=False):
    """Downloads list of Github and Public IPs from ip_bucket

    :param override: redownload IP list, even if file exists in container.
    """

    if not os.path.isfile("/tmp/ips") or override:
        logger.info("IPs not found on lambda container, fetching from s3...")
        try:
            if override:
                invoke_ip_lambda()  # Force update IP list

            s3.download_file(ip_bucket, "ips", "/tmp/ips")
        except Exception as e:
            # File does not exist in the bucket, invoke ip_lambda to generate file and
            # retry download
            logger.info(
                "Could not locate file in bucket, invoking lambda to generate..."
            )
            invoke_ip_lambda()
            s3.download_file(ip_bucket, "ips", "/tmp/ips")


def zip_repo(repo_path: str, repo_name: str) -> str:
    """Creates a zip file of all files in given path

    Creates a zip file called repo_name.zip in /tmp containing all files in repo_path.
    If exclude_git is set, it will delete the .git folder and it will not be included
    in the final zip file.

    :param repo_path:
    :param repo_name:
    :return: Returns full path to created zip file
    """

    logger.info("Creating zipfile...")
    zf = ZipFile("/tmp/" + repo_name.replace("/", "_") + ".zip", "w")
    for dirname, subdirs, files in os.walk(repo_path):
        if exclude_git:
            try:
                subdirs.remove(".git")
            except ValueError:
                pass
        zdirname = dirname[len(repo_path) + 1 :]
        zf.write(dirname, zdirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename), os.path.join(zdirname, filename))
    zf.close()
    return "/tmp/" + repo_name.replace("/", "_") + ".zip"


def push_s3(full_file_path: str, repo_name: str, prefix: str, source_bucket: str):
    """Uploads a file to a given path in S3

    Uploads file from full_file_path to source_bucket in location
    s3://source_bucket/repo_name/prefix/full_file_path with full_file_path stripped of
    /tmp/. Also uploads /tmp/event.json to s3://source_bucket/repo_name/prefix/events/
    using the version id of the uploaded zip as filename

    :param full_file_path: Full path of file to be uploaded. Must be path in /tmp
    :param repo_name: Full name of the git repository, in form username/repository
    :param prefix: Dev or prod prefixes
    :param source_bucket: Name of bucket to upload the source code to
    """

    s3key = "%s/%s/%s" % (repo_name, prefix, full_file_path.replace("/tmp/", ""))
    logger.info("pushing zip to s3://%s/%s" % (source_bucket, s3key))
    data = open(full_file_path, "rb")
    resp = s3.put_object(Bucket=source_bucket, Body=data, Key=s3key)
    logger.info("Response: %s" % resp)
    s3key = "%s/%s/events/%s" % (repo_name, prefix, resp["VersionId"])
    logger.info("pushing event.json to s3://%s/%s" % (source_bucket, s3key))
    data = open("/tmp/event.json", "rb")
    s3.put_object(Bucket=source_bucket, Body=data, Key=s3key)
    logger.info("Completed S3 upload...")


def github_event(event: dict) -> (str, str, str, str):
    """Return repository information for a github repository

    Returns information about a github repository based on incoming API gateway
    event. It filters out events that are not pushes, opened or updated pull request
    and checks whether or not the destination branch matches a provided regex that should
    trigger pipeline.

    :param event: Lambda event information provided by AWS
    :return: remote_url: github ssh url to repository
        prefix: either dev or prod, depending on regex matches
        repo_name: the full name of the repository, in the form username/repository
        branch: The branch that should be cloned, depending on what branch triggered the webhook
    """

    repo_name = event["body-json"]["repository"]["full_name"]

    pr = False

    # Check if the event is a push or pull request, else throws and exception.
    # If event is a pull request, check if the pull request has been opened or updated
    if event["params"]["header"]["X-GitHub-Event"] == "pull_request":
        if not any(
            action in event["body-json"]["action"]
            for action in ["opened", "synchronize"]
        ):
            logger.error(
                "PR action is not opened or synchronize, it is %s"
                % event["body-json"]["action"]
            )
            raise Exception(
                "PR action is not opened or synchronize, it is %s"
                % event["body-json"]["action"]
            )
        pr = True

    elif event["params"]["header"]["X-GitHub-Event"] != "push":
        logger.error(
            "Unknown github event %s" % event["params"]["header"]["X-GitHub-Event"]
        )
        raise Exception(
            "Unknown github event %s" % event["params"]["header"]["X-GitHub-Event"]
        )

    # If it is a pull request, check if the destination branch matches pull request regex.
    # In case of a match, return repository information from event
    if pr:
        regex_bytes = base64.b64decode(event["stage-variables"]["prregexbase64"])
        regex = re.compile(regex_bytes.decode("utf-8"))
        if not regex.match(event["body-json"]["pull_request"]["base"]["ref"]):
            logger.error(
                "PR is not to master, it is to %s"
                % event["body-json"]["pull_request"]["base"]["ref"]
            )
            raise Exception(
                "PR is not to master, it is to %s"
                % event["body-json"]["pull_request"]["base"]["ref"]
            )
        prefix = "dev"
        branch = event["body-json"]["pull_request"]["head"]["ref"]
        remote_url = event["body-json"]["pull_request"]["head"]["repo"]["ssh_url"]
        return remote_url, prefix, repo_name, branch

    # Event is a push, check if it is to a branch matching either dev or prod regex
    #   and set prefix accordingly

    devregex_bytes = base64.b64decode(event["stage-variables"]["devbranchregexbase64"])
    devregex = re.compile(devregex_bytes.decode("utf-8"))

    prodregex_bytes = base64.b64decode(
        event["stage-variables"]["prodbranchregexbase64"]
    )
    prodregex = re.compile(prodregex_bytes.decode("utf-8"))

    if devregex.match(event["body-json"]["ref"].replace("refs/heads/", "")):
        prefix = "dev"
    elif prodregex.match(event["body-json"]["ref"].replace("refs/heads/", "")):
        prefix = "prod"
    else:
        logger.error(
            "Push does not match a registered regex, it is to branch %s"
            % event["body-json"]["ref"]
        )
        raise Exception(
            "Push does not match a registered regex, it is to branch %s"
            % event["body-json"]["ref"]
        )

    branch = event["body-json"]["ref"].replace("refs/heads/", "")
    remote_url = event["body-json"]["repository"]["ssh_url"]

    return remote_url, prefix, repo_name, branch


def bitbucket_event(event: dict) -> (str, str, str, str):
    """Return repository information for a bitbucket repository

    Returns information about a github repository based on incoming API gateway
    event. It filters out events that are not pushes, opened or updated pull request
    and checks whether or not the destination branch matches a provided regex that should
    trigger pipeline.

    :param event: Lambda event information provided by AWS
    :return: remote_url: bitbucket ssh url to repository
        prefix: either dev or prod, depending on regex matches
        repo_name: the full name of the repository, in the form username/repository
        branch: The branch that should be cloned, depending on what branch triggered the webhook
    """

    repo_name = event["body-json"]["repository"]["full_name"]

    pr = False

    # Check if the event is a push or opened/updated pull request, else throws and exception.
    if event["params"]["header"]["X-Event-Key"] == "pullrequest:created":
        pr = True
    elif event["params"]["header"]["X-Event-Key"] == "pullrequest:updated":
        pr = True
    elif event["params"]["header"]["X-Event-Key"] != "repo:push":
        logger.error(
            "Unknown bitbucket event %s" % event["params"]["header"]["X-Event-Key"]
        )
        raise Exception(
            "Unknown bitbucket event %s" % event["params"]["header"]["X-Event-Key"]
        )

    # If it is a pull request, check if the destination branch matches pull request regex.
    # In case of a match, return repository information from event
    if pr:
        regex_bytes = base64.b64decode(event["stage-variables"]["prregexbase64"])
        regex = re.compile(regex_bytes.decode("utf-8"))
        if not regex.match(
            event["body-json"]["pullrequest"]["destination"]["branch"]["name"]
        ):
            logger.error(
                "PR is not to branch matching provided regex, it is %s"
                % event["body-json"]["pullrequest"]["destination"]["branch"]["name"]
            )
            raise Exception(
                "PR is not to to branch matching provided regex, it is %s"
                % event["body-json"]["pullrequest"]["destination"]["branch"]["name"]
            )
        prefix = "dev"  # Should not be run through production pipeline
        branch = event["body-json"]["pullrequest"]["source"]["branch"]["name"]
        remote_url = https_url_to_ssh_url(
            event["body-json"]["pullrequest"]["source"]["repository"]["links"]["html"][
                "href"
            ]
        )
        return remote_url, prefix, repo_name, branch

    # Event is a push, check if it is to a branch matching either dev or prod regex
    #   and set prefix accordingly
    devregex_bytes = base64.b64decode(event["stage-variables"]["devbranchregexbase64"])
    devregex = re.compile(devregex_bytes.decode("utf-8"))

    prodregex_bytes = base64.b64decode(
        event["stage-variables"]["prodbranchregexbase64"]
    )
    prodregex = re.compile(prodregex_bytes.decode("utf-8"))

    if devregex.match(
        event["body-json"]["push"]["changes"][0]["new"]["links"]["html"]["href"].split(
            "/"
        )[-1]
    ):
        prefix = "dev"

    elif prodregex.match(
        event["body-json"]["push"]["changes"][0]["new"]["links"]["html"]["href"].split(
            "/"
        )[-1]
    ):
        prefix = "prod"
    else:
        logger.error(
            "Push is not to master, it is to %s"
            % event["body-json"]["push"]["changes"][0]["new"]["links"]["html"][
                "href"
            ].split("/")[-1]
        )
        raise Exception(
            "Push is not to master it is to %s"
            % event["body-json"]["push"]["changes"][0]["new"]["links"]["html"][
                "href"
            ].split("/")[-1]
        )

    branch = event["body-json"]["push"]["changes"][0]["new"]["name"]
    remote_url = https_url_to_ssh_url(
        event["body-json"]["repository"]["links"]["html"]["href"]
    )

    return remote_url, prefix, repo_name, branch


def https_url_to_ssh_url(url: str) -> str:
    """Convert https url to git ssh url

    :param url:  https url to be converted
    :return: Returns git ssh url as string
    """

    if ".git" in url[-4:]:
        return url.replace("https://", "git@").replace("/", ":", 1)
    return url.replace("https://", "git@").replace("/", ":", 1) + ".git"


def ssh_url_to_https_url(url: str) -> str:
    """Convert git ssh url to https url

    :param url:  ssh url to be converted
    :return: Returns git https url as string
    """

    if ".git" in url[-4:]:
        return url.replace(":", "/", 1).replace("git@", "https://")
    return url.replace(":", "/", 1).replace("git@", "https://") + ".git"


def check_if_secure_ip(event: dict) -> bool:
    """Check if source IP is part of the list of public endpoint IPs for Bitbucket or GitHub

    :param event: Lambda event information provided by AWS
    :return: Returns True if source IP is in ip list, False otherwise
    """
    f = open("/tmp/ips", "r")
    # Source IP ranges to allow requests from,
    # if the IP is in one of these the request will not be checked for an api key
    ipranges = []
    for i in f.read().split(","):
        ipranges.append(ip_network("%s" % i))

    # APIKeys, it is recommended to use a different API key for each repo that uses this function
    ip = ip_address(event["context"]["source-ip"])

    # Check if the request comes from an authorized IP or has a given API key
    for net in ipranges:
        if ip in net:
            return True

    return False


def lambda_handler(event: dict, context):
    """Uploads a zip file of source code from a given git repository based on webhook event

    Gets triggered from a webhook event to API gateway. Clones the repository, zips it and
    uploads the source code to a given S3 bucket. Currently only supports Bitbucket Cloud
    and Github

    :param event: Lambda event information provided by AWS
    :param context: Lambda context information provided by AWS - Not used
    """

    logger.info(event)
    key_bucket = event["context"]["key-bucket"]
    source_bucket = event["context"]["source-bucket"]
    pubkey = event["context"]["public-key"]

    get_ips()  # Get list of public IPs from Github and Bitbucket
    secure = check_if_secure_ip(event)

    apikeys = event["context"]["api-secrets"].split(",")

    # NOTE: These have not been tested against recent API events, and may not work properly.
    if "X-Git-Token" in list(event["params"]["header"].keys()):
        if event["params"]["header"]["X-Git-Token"] in apikeys:
            secure = True
    if "X-Gitlab-Token" in list(event["params"]["header"].keys()):
        if event["params"]["header"]["X-Gitlab-Token"] in apikeys:
            secure = True
    if "X-Hub-Signature" in list(event["params"]["header"].keys()):
        for k in apikeys:
            if "use-sha256" in event["context"]:
                k1 = hmac.new(
                    str(k).encode,
                    str.encode(event["context"]["raw-body"]), hashlib.sha256
                ).hexdigest()
                k2 = str(
                    event["params"]["header"]["X-Hub-Signature"].replace("sha256=", "")
                )
            else:
                k1 = hmac.new(
                    str(k).encode,
                    str.encode(event["context"]["raw-body"]), hashlib.sha1
                ).hexdigest()
                k2 = str(
                    event["params"]["header"]["X-Hub-Signature"].replace("sha1=", "")
                )
            if k1 == k2:
                secure = True

    if not secure:
        # Invoke FindGitPublicIPs to update list, and recheck for match. Avoids issues with outdated list
        get_ips(override=True)
        if not check_if_secure_ip(event):
            logger.error("Source IP %s is not allowed" % event["context"]["source-ip"])
            raise Exception(
                "Source IP %s is not allowed" % event["context"]["source-ip"]
            )

    # Check what git host sent webhook, and process accordingly
    if "GitHub" in event["params"]["header"]["User-Agent"]:
        remote_url, prefix, repo_name, branch = github_event(event)
    elif "Bitbucket" in event["params"]["header"]["User-Agent"]:
        remote_url, prefix, repo_name, branch = bitbucket_event(event)
    else:
        logger.error("Unknown git host %s" % event["params"]["header"]["User-Agent"])
        raise Exception

    repo_path = "/tmp/%s" % repo_name
    get_keys(key_bucket, pubkey)  # Get RSA key pair to authenticate with the repository

    # Custom ssh command to be used with git to use the correct private key.
    git_ssh_cmd = "ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no"
    try:
        logger.info("Cloning repository from %s" % remote_url)
        Repo.clone_from(
            remote_url,
            repo_path,
            depth=1,
            branch=branch,
            env=dict(GIT_SSH_COMMAND=git_ssh_cmd),
        )
    except (exc.NoSuchPathError, exc.InvalidGitRepositoryError) as e:
        logger.error(
            "Error pulling new repo %s, branch %s in %s"
            % (remote_url, branch, repo_path)
        )
        raise Exception(
            "Error pulling new repo %s, branch %s in %s"
            % (remote_url, branch, repo_path)
        )
    except exc.GitCommandError as e:
        # If exception is a command error, it is likely that the private key does not have access
        # to the repository. Convert ssh url to https and attempt to clone again. If it fails, the repository
        # is not public.
        logger.error("Error running command, trying with https...")
        remote_url = ssh_url_to_https_url(remote_url)
        logger.info("Cloning repository from %s" % remote_url)
        Repo.clone_from(
            remote_url,
            repo_path,
            depth=1,
            branch=branch,
            env=dict(GIT_SSH_COMMAND=git_ssh_cmd),
        )

    # Store the event from lambda in separate folder in bucket, to provide git information
    # to pipeline steps or functions
    f = open("/tmp/event.json", "wb")
    event_json = json.dumps(event)
    f.write(event_json.encode())
    f.close()

    zipfile = zip_repo(repo_path, repo_name)
    push_s3(zipfile, repo_name, prefix, source_bucket)
    logger.info("Cleanup Lambda container...")
    shutil.rmtree(repo_path)
    os.remove(zipfile)
    os.remove("/tmp/id_rsa")
    os.remove("/tmp/id_rsa.pub")
    return "Successfully uploaded %s" % repo_name
