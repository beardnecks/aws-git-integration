#  Copyright 2016 Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
#  This file is licensed to you under the AWS Customer Agreement (the "License").
#  You may not use this file except in compliance with the License.
#  A copy of the License is located at http://aws.amazon.com/agreement/ .
#  This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.
#  See the License for the specific language governing permissions and limitations under the License.

from pygit2 import Keypair, discover_repository, Repository, clone_repository, RemoteCallbacks, GitError
from boto3 import client
import os
import stat
import shutil
from zipfile import ZipFile
from ipaddress import ip_network, ip_address
import logging
import hmac
import hashlib
import distutils.util
# Regex
import re

# If true the function will not include .git folder in the zip
exclude_git = bool(distutils.util.strtobool(os.environ['ExcludeGit']))

# If true the function will delete all files at the end of each invocation, useful if you run into storage space
# constraints, but will slow down invocations as each invoke will need to checkout the entire repo
cleanup = False

key = 'enc_key'

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers[0].setFormatter(logging.Formatter('[%(asctime)s][%(levelname)s] %(message)s'))
logging.getLogger('boto3').setLevel(logging.ERROR)
logging.getLogger('botocore').setLevel(logging.ERROR)

s3 = client('s3')
kms = client('kms')


def write_key(filename, contents):
    logger.info('Writing keys to /tmp/...')
    mode = stat.S_IRUSR | stat.S_IWUSR
    umask_original = os.umask(0)
    try:
        handle = os.fdopen(os.open(filename, os.O_WRONLY | os.O_CREAT, mode), 'wb')
    finally:
        os.umask(umask_original)

    handle.write(contents + b"\n")
    handle.close()


def get_keys(keybucket, pubkey, update=False):
    if not os.path.isfile('/tmp/id_rsa') or not os.path.isfile('/tmp/id_rsa.pub') or update:
        logger.info('Keys not found on Lambda container, fetching from S3...')
        enckey = s3.get_object(Bucket=keybucket, Key=key)['Body'].read()
        privkey = kms.decrypt(CiphertextBlob=enckey)['Plaintext']
        write_key('/tmp/id_rsa', privkey)
        write_key('/tmp/id_rsa.pub', str.encode(pubkey))
    return Keypair('git', '/tmp/id_rsa.pub', '/tmp/id_rsa', '')


def init_remote(repo, name, url):
    remote = repo.remotes.create(name, url, '+refs/*:refs/*')
    return remote


def create_repo(repo_path, remote_url, creds):
    if os.path.exists(repo_path):
        logger.info('Cleaning up repo path...')
        shutil.rmtree(repo_path)
    repo = clone_repository(remote_url, repo_path, callbacks=creds)

    return repo


def pull_repo(repo, branch_name, remote_url, creds):
    remote_exists = False
    for r in repo.remotes:
        if r.url == remote_url:
            remote_exists = True
            remote = r
    if not remote_exists:
        remote = repo.create_remote('origin', remote_url)
    logger.info('Fetching and merging changes from %s branch %s', remote_url, branch_name)
    remote.fetch(callbacks=creds)
    if branch_name.startswith('tags/'):
        ref = 'refs/' + branch_name
    else:
        ref = 'refs/remotes/origin/' + branch_name
    remote_branch_id = repo.lookup_reference(ref).target
    repo.checkout_tree(repo.get(remote_branch_id))
    # branch_ref = repo.lookup_reference('refs/heads/' + branch_name)
    # branch_ref.set_target(remote_branch_id)
    repo.head.set_target(remote_branch_id)
    return repo


def zip_repo(repo_path, repo_name):
    logger.info('Creating zipfile...')
    zf = ZipFile('/tmp/' + repo_name.replace('/', '_') + '.zip', 'w')
    for dirname, subdirs, files in os.walk(repo_path):
        if exclude_git:
            try:
                subdirs.remove('.git')
            except ValueError:
                pass
        zdirname = dirname[len(repo_path) + 1:]
        zf.write(dirname, zdirname)
        for filename in files:
            zf.write(os.path.join(dirname, filename), os.path.join(zdirname, filename))
    zf.close()
    return '/tmp/' + repo_name.replace('/', '_') + '.zip'


def push_s3(filename, repo_name, prefix, outputbucket):
    s3key = '%s/%s/%s' % (repo_name, prefix, filename.replace('/tmp/', ''))
    logger.info('pushing zip to s3://%s/%s' % (outputbucket, s3key))
    data = open(filename, 'rb')
    s3.put_object(Bucket=outputbucket, Body=data, Key=s3key)
    logger.info('Completed S3 upload...')


def lambda_handler(event, context):
    keybucket = event['context']['key-bucket']
    outputbucket = event['context']['output-bucket']
    pubkey = event['context']['public-key']
    # Source IP ranges to allow requests from,
    # if the IP is in one of these the request will not be chacked for an api key
    ipranges = []
    for i in event['context']['allowed-ips'].split(','):
        ipranges.append(ip_network('%s' % i))
    # APIKeys, it is recommended to use a different API key for each repo that uses this function
    apikeys = event['context']['api-secrets'].split(',')
    ip = ip_address(event['context']['source-ip'])
    # Check if it is a pull request(PR) or not.
    pr = False
    # Unsure wether this if statement works or not, must be tested. 
    # Figure out how to check if event == pull_request.
    if event['params']['header']['X-GitHub-Event'] == 'pull_request':
        pr = True
    # Check if it is a push or not
    push = False
    # Unsure wether this if statement works or not, must be tested. 
    if event['params']['header']['X-GitHub-Event'] == 'push':
        push = True

    secure = False
    for net in ipranges:
        if ip in net:
            secure = True
    if 'X-Git-Token' in list(event['params']['header'].keys()):
        if event['params']['header']['X-Git-Token'] in apikeys:
            secure = True
    if 'X-Gitlab-Token' in list(event['params']['header'].keys()):
        if event['params']['header']['X-Gitlab-Token'] in apikeys:
            secure = True
    if 'X-Hub-Signature' in list(event['params']['header'].keys()):
        for k in apikeys:
            if 'use-sha256' in event['context']:
                k1 = hmac.new(str(k), str(event['context']['raw-body']), hashlib.sha256).hexdigest()
                k2 = str(event['params']['header']['X-Hub-Signature'].replace('sha256=', ''))
            else:
                k1 = hmac.new(str(k), str(event['context']['raw-body']), hashlib.sha1).hexdigest()
                k2 = str(event['params']['header']['X-Hub-Signature'].replace('sha1=', ''))
            if k1 == k2:
                secure = True
    # TODO: Add the ability to clone TFS repo using SSH keys
    try:
        # GitHub
        full_name = event['body-json']['repository']['full_name']
    except KeyError:
        try:
            # BitBucket #14
            full_name = event['body-json']['repository']['fullName']
        except KeyError:
            try:
                # GitLab
                full_name = event['body-json']['repository']['path_with_namespace']
            except KeyError:
                try:
                    # GitLab 8.5+
                    full_name = event['body-json']['project']['path_with_namespace']
                except KeyError:
                    try:
                        # BitBucket server
                        full_name = event['body-json']['repository']['name']
                    except KeyError:
                        # BitBucket pull-request
                        full_name = event['body-json']['pullRequest']['fromRef']['repository']['name']
    if not secure:
        logger.error('Source IP %s is not allowed' % event['context']['source-ip'])
        raise Exception('Source IP %s is not allowed' % event['context']['source-ip'])

    # Check if there is PR or a push
    if not (pr or push):
        logger.error('This is not a Pull Request or a Push')
        raise Exception('This is not a Pull Request or a Push')

    # Check if: Opened PR
    if pr:
        if 'action' in event['body-json'] and event['body-json']['action'] != 'opened' and not push:
            logger.error('PR action is not opened, it is %s' % event['body-json']['action'])
            raise Exception('PR action is not opened, it is %s' % event['body-json']['action'])
    # Check if PR to master
    # Regex object, string that starts with master, widlcard after. (master*)
    regex = re.compile("^master")
    if pr:
        if ('base' in event['body-json']['pull_request'] and not regex.match(
                event['body-json']['pull_request']['base']['ref'])):
            logger.error('PR is not to master, it is %s' % event['body-json']['pull_request']['base']['ref'])
            raise Exception('PR is not to master, it is %s' % event['body-json']['pull_request']['base']['ref'])
        else:
            prefix = "dev"

    # Check if: Push to master.
    regex = re.compile("^refs/heads/master$")
    if push:
        if 'ref' in event['body-json'] and not regex.match(event['body-json']['ref']) and not pr:
            logger.error('Push is not to master, it is to %s' % event['body-json']['ref'])
            raise Exception('Push is not to master it is to %s' % event['body-json']['ref'])
        else:
            prefix = "prod"

    # GitHub publish event
    if 'action' in event['body-json'] and event['body-json']['action'] == 'published':
        branch_name = 'tags/%s' % event['body-json']['release']['tag_name']
        repo_name = full_name + '/release'
    else:
        repo_name = full_name
        try:
            # branch names should contain [name] only, tag names - "tags/[name]"
            branch_name = event['body-json']['ref'].replace('refs/heads/', '').replace('refs/tags/', 'tags/')
        except KeyError:
            try:
                # Bibucket server
                branch_name = event['body-json']['push']['changes'][0]['new']['name']
            except Exception:
                branch_name = 'master'
    try:
        # GitLab
        remote_url = event['body-json']['project']['git_ssh_url']
    except Exception:
        try:
            remote_url = 'git@' \
                         + event['body-json']['repository']['links']['html']['href'].replace('https://',
                                                                                             '').replace('/',
                                                                                                         ':',
                                                                                                         1) + '.git'
        except Exception:
            try:
                # GitHub
                remote_url = event['body-json']['repository']['ssh_url']
            except Exception:
                # Bitbucket
                try:
                    for i, url in enumerate(event['body-json']['repository']['links']['clone']):
                        if url['name'] == 'ssh':
                            ssh_index = i
                    remote_url = event['body-json']['repository']['links']['clone'][ssh_index]['href']
                except Exception:
                    # BitBucket pull-request
                    for i, url in enumerate(
                            event['body-json']['pullRequest']['fromRef']['repository']['links']['clone']):
                        if url['name'] == 'ssh':
                            ssh_index = i

                    remote_url = \
                        event['body-json']['pullRequest']['fromRef']['repository']['links']['clone'][ssh_index]['href']
    repo_path = '/tmp/%s' % repo_name
    creds = RemoteCallbacks(credentials=get_keys(keybucket, pubkey), )
    try:
        repository_path = discover_repository(repo_path)
        repo = Repository(repository_path)
        logger.info('found existing repo, using that...')
    except Exception:
        logger.info('creating new repo for %s in %s' % (remote_url, repo_path))
        repo = create_repo(repo_path, remote_url, creds)

    try:
        pull_repo(repo, branch_name, remote_url, creds)
    except GitError as e:
        if "conflicts" in e:
            logger.info('Found repo conflicts, redownloading repo')
            repo = create_repo(repo_path, remote_url, creds)
            pull_repo(repo, branch_name, remote_url, creds)

    zipfile = zip_repo(repo_path, repo_name)
    push_s3(zipfile, repo_name, prefix, outputbucket)
    if cleanup:
        logger.info('Cleanup Lambda container...')
        shutil.rmtree(repo_path)
        os.remove(zipfile)
        os.remove('/tmp/id_rsa')
        os.remove('/tmp/id_rsa.pub')
    return 'Successfully updated %s' % repo_name
