#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import io
import json
import ipaddress
from flask import Flask, request, abort
import argparse
from gitlab_api import GitlabApi
from Mailer import send_mail

app = Flask(__name__)

REPOS_JSON_PATH = None
WHITELIST_IP = None
repos = None


@app.route("/", methods=['GET', 'POST'])
def index():
    if request.method == "GET":
        return 'OK'
    elif request.method == "POST":
        # Store the IP address of the requester
        request_ip = ipaddress.ip_address(u'{0}'.format(request.remote_addr))

        # Check the POST source
        if not WHITELIST_IP is None:
            for block in [WHITELIST_IP]:
                if ipaddress.ip_address(request_ip) in ipaddress.ip_network(block):
                    break  # the remote_addr is within the network range of GitLab.
            else:
                abort(403)

        payload = json.loads(request.data)

        if payload['object_kind'] in ['tag_push', 'merge_request']:
            repo_meta = {
                'homepage': payload['project']['homepage'],
            }

            # load configure base on homepage.
            repo = repos.get(repo_meta['homepage'], None)
            private_token = repo.get('private_token', None)

        if payload['object_kind'] == "tag_push":
            if payload['message'] is None:
                # delete tag
                return "Delete Tag"
            else:
                # create new tag
                tag_ref = payload['ref'].split('/')[-1]
                tag_project_id = payload['project_id']
                # test_branch get from repos.json configure file.
                test_branch = repo['tag_push'].get('test_branch', None)

                gl = GitlabApi(repo_meta['homepage'], private_token)
                response = gl.get("projects/" + str(tag_project_id) + "/repository/branches")
                for branch_info in response:
                    if test_branch == branch_info['name']:
                        content = test_branch + " already exists !<br>"

                        delete_info = gl.delete("projects/" + str(tag_project_id) + "/repository/branches/" + test_branch)
                        if delete_info:
                            content += "Delete test branch: " + test_branch + "<br>"
                        break
                else:
                    content = ""

                # base on tag_ref, create v1.0-test branch.
                data = {'branch': test_branch, 'ref': tag_ref}
                ok = gl.post("projects/" + str(tag_project_id) + "/repository/branches", data)
                if ok:
                    content += "Create new test branch (" + test_branch + ") success.<br>"

                to_list = repo.get("mail_to", None)
                subject = "GitLab Notifications"
                # Notice: Modified ME
                # email content change to chinese
                # UnicodeDecodeError: 'ascii' codec can't decode byte 0xe5 in position 0: ordinal not in range(128)

                # content = "基于 tag: ".encode('utf-8') + tag_ref + " 产生最新的 测试(".encode('utf-8') + test_branch +
                # ")分支, 可进行测试的构建部署.".encode('utf-8')
                content += "Base on tag: " + tag_ref + ", Create the latest test (" + test_branch + \
                           ") branch, then you can do test build/deploy."
                status = send_mail(to_list, subject, content)
                if status:
                    return json.dumps(response)

        if payload['object_kind'] == "merge_request":

            # merge object attributes
            merge_attri = payload['object_attributes']
            target_pro_id = merge_attri['target_project_id']
            project_branch = merge_attri['target_branch']

            # Modified ME
            # Notice other feature, develop branch have new changes.

            if merge_attri['state'] == "merged":
                gl = GitlabApi(repo_meta['homepage'], private_token)
                data = {'tag_name': tag_name, 'ref': project_branch}
                response = gl.post("projects/" + str(target_pro_id) + "/repository/tags", data)

                return json.dumps(response)

        # common for events
        # if payload['object_kind'] in ['push', 'issue']:
        #    repo_meta = {
        #        'homepage': payload['repository']['homepage'],
        #    }
        #
        #    repo = repos.get(repo_meta['homepage'], None)
        #    private_token = repo.get('private_token', None)
        #
        # if not repo:
        #    return json.dumps({'error': "nothing to do for " + str(repo_meta)})
        #
        # if payload['object_kind'] == "push":
        #    match = re.match(r"refs/heads/(?P<branch>.*)", payload['ref'])
        #    if match:
        #        repo_meta['branch'] = match.groupdict()['branch']
        #    else:
        #        return json.dumps({'error': "unable to determine pushed branch"})
        #
        #    push = repo.get("push", None)
        #    if push:
        #        branch = push.get(repo_meta['branch'], None)
        #        if not branch:
        #            branch = repo['push'].get("other", None)
        #        if branch:
        #            branch_actions = branch.get("actions", None)
        #
        #            if branch_actions:
        #                for action in branch_actions:
        #                    try:
        #                        subp = subprocess.Popen(action, cwd=branch.get("path", "."), shell=True)
        #                        subp.wait()
        #                    except Exception as e:
        #                        print e
        #    return 'OK'

        # if payload['object_kind'] == "issue":
        #    issue = repo.get("issue", None)
        #    if issue:
        #        # notification for new issue
        #        if issue.get("user_notify", None) and payload['object_attributes']['action'] == "open":
        #            if not private_token:
        #                abort(403)
        #            gl = GitlabApi(repo_meta['homepage'], private_token)
        #            notify = issue['user_notify']
        #            description = payload['object_attributes']['description']
        #            usernames = []
        #            for n in notify:
        #                username_match = re.match("^@[a-zA-Z0-9_.+-]+$", n)
        #                if username_match:
        #                    # simple username
        #                    usernames.append(n)
        #                else:
        #                    # try to pull the email from the issue body
        #                    # and derive the username from that
        #                    body_match = re.match(n, description)
        #                    if body_match and private_token:
        #                        email = body_match.group(1)
        #                        username = gl.lookup_username(email)
        #                        if username:
        #                            usernames.append("@" + username)
        #            # narrow down to unique names
        #            usernames = list(set(usernames))
        #            if len(usernames) > 0:
        #                project_id = payload['object_attributes']['project_id']
        #                issue_id = payload['object_attributes']['id']
        #                gl.comment_on_issue(project_id, issue_id, "Automatic mention for %s" % (" and ".join(usernames)))
        #
        #    return 'OK'

        # unknown event type
        return json.dumps({'error': "wrong event type"})


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="gitlab webhook receiver")
    parser.add_argument("-c", "--config", action="store", help="path to repos configuration", required=True)
    parser.add_argument("-p", "--port", action="store", help="server port", required=False, default=8080)
    parser.add_argument("--allow", action="store", help="whitelist Gitlab IP block", required=False, default=None)
    parser.add_argument("--debug", action="store_true", help="enable debug output", required=False, default=False)
    

    args = parser.parse_args()

    port_number = int(args.port)

    REPOS_JSON_PATH = args.config
    try:
        repos = json.loads(io.open(REPOS_JSON_PATH, 'r').read())
    except:
        print "Error opening repos file %s -- check file exists and is valid json" % REPOS_JSON_PATH
        raise

    if args.allow:
        WHITELIST_IP = unicode(args.allow, "utf-8")

    if args.debug:
        app.debug = True

    app.run(host="0.0.0.0", port=port_number)
