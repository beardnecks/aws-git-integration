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
import logging
import os
# Regex
import re
import shutil
import stat
from ipaddress import ip_address, ip_network
from zipfile import ZipFile

from boto3 import client
from git import Remote, Repo, exc

# If true the function will not include .git folder in the zip
exclude_git = bool(distutils.util.strtobool(os.environ["ExcludeGit"]))
ip_bucket = os.environ["IPBucket"]
ip_lambda = os.environ["IPLambda"]


key = "enc_key"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers[0].setFormatter(
    logging.Formatter("[%(asctime)s][%(levelname)s] %(message)s")
)
logging.getLogger("boto3").setLevel(logging.ERROR)
logging.getLogger("botocore").setLevel(logging.ERROR)

s3 = client("s3")
kms = client("kms")


def write_key(filename, contents):
    logger.info("Writing keys to /tmp/...")
    mode = stat.S_IRUSR | stat.S_IWUSR
    umask_original = os.umask(0)
    try:
        handle = os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, mode), "wb")
    finally:
        os.umask(umask_original)

    handle.write(contents + b"\n")
    handle.close()


def get_keys(keybucket, pubkey, update=False):
    if (
        not os.path.isfile("/tmp/id_rsa")
        or not os.path.isfile("/tmp/id_rsa.pub")
        or update
    ):
        logger.info("Keys not found on Lambda container, fetching from S3...")
        enckey = s3.get_object(Bucket=keybucket, Key=key)["Body"].read()
        privkey = kms.decrypt(CiphertextBlob=enckey)["Plaintext"]
        write_key("/tmp/id_rsa", privkey)
        write_key("/tmp/id_rsa.pub", str.encode(pubkey))


def get_ips():
    if not os.path.isfile("/tmp/ips"):
        logger.info("IPs not found on lambda container, fetching from s3...")
        try:
            s3.download_file(ip_bucket, "ips", "/tmp/ips")
        except Exception as e:
            lambda_client = client("lambda")
            lambda_client.invoke(FunctionName="")
            s3.download_file(ip_bucket, "ips", "/tmp/ips")



def init_remote(repo, name, url):
    remote = repo.remotes.create(name, url, "+refs/*:refs/*")
    return remote


def create_repo(repo_path, remote_url):
    if os.path.exists(repo_path):
        logger.info("Cleaning up repo path...")
        shutil.rmtree(repo_path)
    repo = Repo.clone_from(remote_url, repo_path, depth=1)

    return repo


def pull_repo(repo, branch_name, remote_url):
    remote_exists = False
    for r in repo.remotes:
        if r.url == remote_url:
            remote_exists = True
            remote = r
    if not remote_exists:
        remote = repo.create_remote("origin", remote_url)
    logger.info(
        "Fetching and merging changes from %s branch %s", remote_url, branch_name
    )
    remote.fetch()
    if branch_name.startswith("tags/"):
        ref = "refs/" + branch_name
    else:
        ref = "refs/remotes/origin/" + branch_name
    remote_branch_id = repo.lookup_reference(ref).target
    repo.checkout_tree(repo.get(remote_branch_id))
    # branch_ref = repo.lookup_reference('refs/heads/' + branch_name)
    # branch_ref.set_target(remote_branch_id)
    repo.head.set_target(remote_branch_id)
    return repo


def zip_repo(repo_path, repo_name):
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


def push_s3(filename, repo_name, prefix, outputbucket):
    s3key = "%s/%s/%s" % (repo_name, prefix, filename.replace("/tmp/", ""))
    logger.info("pushing zip to s3://%s/%s" % (outputbucket, s3key))
    data = open(filename, "rb")
    s3.put_object(Bucket=outputbucket, Body=data, Key=s3key)
    logger.info("Completed S3 upload...")


def github_event(event: dict):
    full_name = event["body-json"]["repository"]["full_name"]

    # Check if it is a pull request(PR) or not.
    pr = False
    # Unsure wether this if statement works or not, must be tested.
    # Figure out how to check if event == pull_request.
    if event["params"]["header"]["X-GitHub-Event"] == "pull_request":
        pr = True

    # Check if it is a push or not
    push = False
    # Unsure wether this if statement works or not, must be tested.
    if event["params"]["header"]["X-GitHub-Event"] == "push":
        push = True

    # Check if there is PR or a push
    if not (pr or push):
        logger.error("This is not a Pull Request or a Push")
        raise Exception("This is not a Pull Request or a Push")

    # Check if: Opened PR
    if pr:
        if (
            "action" in event["body-json"]
            and event["body-json"]["action"] != "opened"
            and not push
        ):
            logger.error(
                "PR action is not opened, it is %s" % event["body-json"]["action"]
            )
            raise Exception(
                "PR action is not opened, it is %s" % event["body-json"]["action"]
            )

    # Check if PR to master
    # Regex object, string that starts with master, widlcard after. (master*)
    if pr:
        regex_bytes = base64.b64decode(event["stage-variables"]["prregexbase64"])
        regex = re.compile(regex_bytes.decode("utf-8"))
        if "base" in event["body-json"]["pull_request"] and not regex.match(
            event["body-json"]["pull_request"]["base"]["ref"]
        ):
            logger.error(
                "PR is not to master, it is %s"
                % event["body-json"]["pull_request"]["base"]["ref"]
            )
            raise Exception(
                "PR is not to master, it is %s"
                % event["body-json"]["pull_request"]["base"]["ref"]
            )
        else:
            prefix = "dev"

    # Check if: Push to master.
    if push:
        regex_bytes = base64.b64decode(event["stage-variables"]["branchregexbase64"])
        regex = re.compile(regex_bytes.decode("utf-8"))
        if (
            "ref" in event["body-json"]
            and not regex.match(event["body-json"]["ref"])
            and not pr
        ):
            logger.error(
                "Push is not to master, it is to %s" % event["body-json"]["ref"]
            )
            raise Exception(
                "Push is not to master it is to %s" % event["body-json"]["ref"]
            )
        else:
            prefix = "prod"

    repo_name = full_name

    remote_url = event["body-json"]["repository"]["ssh_url"]

    return remote_url, prefix, repo_name


def bitbucket_event(event: dict):
    repo_name = event["body-json"]["repository"]["full_name"]

    # Check what type of event it is
    pr = False
    push = False

    if event["params"]["header"]["X-Event-Key"] == "pullrequest:created":
        pr = True
    elif event["params"]["header"]["X-Event-Key"] == "repo:push":
        push = True

    # Check if there is PR or a push
    if not (pr or push):
        logger.error("This is not a Pull Request or a Push")
        raise Exception("This is not a Pull Request or a Push")

    # Check if: Opened PR
    if pr:
        if (
            "action" in event["body-json"]
            and event["body-json"]["action"] != "opened"
            and not push
        ):
            logger.error(
                "PR action is not opened, it is %s" % event["body-json"]["action"]
            )
            raise Exception(
                "PR action is not opened, it is %s" % event["body-json"]["action"]
            )

    # Check if PR to master
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

    # Check if: Push to master.
    if push:
        regex_bytes = base64.b64decode(event["stage-variables"]["branchregexbase64"])
        regex = re.compile(regex_bytes.decode("utf-8"))
        if (
            "ref" in event["body-json"]
            and not regex.match(
                event["body-json"]["push"]["changes"][0]["new"]["links"]["html"][
                    "href"
                ].split("/")[-1]
            )
            and not pr
        ):
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
        prefix = "prod"  # Run through production pipeline

    remote_url = https_url_to_ssh_url(
        event["body-json"]["repository"]["links"]["html"]["href"]
    )

    return remote_url, prefix, repo_name


def https_url_to_ssh_url(url: str):
    return "git@" + url.replace("https://", "").replace("/", ":", 1) + ".git"


def lambda_handler(event: dict, context):
    print(type(event))
    print(event)  # TODO: Remove debug
    keybucket = event["context"]["key-bucket"]
    outputbucket = event["context"]["output-bucket"]
    pubkey = event["context"]["public-key"]

    get_ips()
    f = open("/tmp/ips", "r")
    # Source IP ranges to allow requests from,
    # if the IP is in one of these the request will not be chacked for an api key
    ipranges = []
    for i in f.read().split(","):
        ipranges.append(ip_network("%s" % i))
    # APIKeys, it is recommended to use a different API key for each repo that uses this function
    apikeys = event["context"]["api-secrets"].split(",")
    ip = ip_address(event["context"]["source-ip"])

    secure = False
    for net in ipranges:
        if ip in net:
            secure = True
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
                    str(k), str(event["context"]["raw-body"]), hashlib.sha256
                ).hexdigest()
                k2 = str(
                    event["params"]["header"]["X-Hub-Signature"].replace("sha256=", "")
                )
            else:
                k1 = hmac.new(
                    str(k), str(event["context"]["raw-body"]), hashlib.sha1
                ).hexdigest()
                k2 = str(
                    event["params"]["header"]["X-Hub-Signature"].replace("sha1=", "")
                )
            if k1 == k2:
                secure = True

    try:
        # GitHub
        full_name = event["body-json"]["repository"]["full_name"]
    except KeyError:
        try:
            # BitBucket #14
            full_name = event["body-json"]["repository"]["fullName"]
        except KeyError:
            try:
                # GitLab
                full_name = event["body-json"]["repository"]["path_with_namespace"]
            except KeyError:
                try:
                    # GitLab 8.5+
                    full_name = event["body-json"]["project"]["path_with_namespace"]
                except KeyError:
                    try:
                        # BitBucket server
                        full_name = event["body-json"]["repository"]["name"]
                    except KeyError:
                        # BitBucket pull-request
                        full_name = event["body-json"]["pullRequest"]["fromRef"][
                            "repository"
                        ]["name"]
    if not secure:
        logger.error("Source IP %s is not allowed" % event["context"]["source-ip"])
        raise Exception("Source IP %s is not allowed" % event["context"]["source-ip"])

    # Check what git host sent webhook, and process accordingly
    if "GitHub" in event["params"]["header"]["User-Agent"]:
        remote_url, prefix, repo_name = github_event(event)
    elif "Bitbucket" in event["params"]["header"]["User-Agent"]:
        remote_url, prefix, repo_name = bitbucket_event(event)
    else:
        logger.error("Unknown git host %s" % event["params"]["header"]["User-Agent"])
        raise Exception

    # try:
    #     # GitLab
    #     remote_url = event["body-json"]["project"]["git_ssh_url"]
    # except Exception:
    #     try:
    #         remote_url = (
    #                 "git@"
    #                 + event["body-json"]["repository"]["links"]["html"]["href"]
    #                 .replace("https://", "")
    #                 .replace("/", ":", 1)
    #                 + ".git"
    #         )
    #     except Exception:
    #         try:
    #             # GitHub
    #             remote_url = event["body-json"]["repository"]["ssh_url"]
    #         except Exception:
    #             # Bitbucket
    #             try:
    #                 for i, url in enumerate(
    #                         event["body-json"]["repository"]["links"]["clone"]
    #                 ):
    #                     if url["name"] == "ssh":
    #                         ssh_index = i
    #                 remote_url = event["body-json"]["repository"]["links"]["clone"][
    #                     ssh_index
    #                 ]["href"]
    #             except Exception:
    #                 # BitBucket pull-request
    #                 for i, url in enumerate(
    #                         event["body-json"]["pullRequest"]["fromRef"]["repository"][
    #                             "links"
    #                         ]["clone"]
    #                 ):
    #                     if url["name"] == "ssh":
    #                         ssh_index = i
    #
    #                 remote_url = event["body-json"]["pullRequest"]["fromRef"][
    #                     "repository"
    #                 ]["links"]["clone"][ssh_index]["href"]

    repo_path = "/tmp/%s" % repo_name
    # creds = RemoteCallbacks(credentials=get_keys(keybucket, pubkey), )
    get_keys(keybucket, pubkey)
    git_ssh_cmd = "ssh -i /tmp/id_rsa -o StrictHostKeyChecking=no"
    try:
        logger.info("Cloning repository from %s" % remote_url)
        Repo.clone_from(
            remote_url, repo_path, depth=1, env=dict(GIT_SSH_COMMAND=git_ssh_cmd)
        )
    except (exc.NoSuchPathError, exc.InvalidGitRepositoryError) as e:
        logger.error("Error pulling new repo for %s in %s" % (remote_url, repo_path))
    zipfile = zip_repo(repo_path, repo_name)
    push_s3(zipfile, repo_name, prefix, outputbucket)
    logger.info("Cleanup Lambda container...")
    shutil.rmtree(repo_path)
    os.remove(zipfile)
    os.remove("/tmp/id_rsa")
    os.remove("/tmp/id_rsa.pub")
    return "Successfully updated %s" % repo_name
