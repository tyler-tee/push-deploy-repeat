import hmac
import hashlib
from ipaddress import ip_address, ip_network
import json
import os
import requests
from flask import Blueprint, jsonify, request
import git


update_server = Blueprint("update", __name__)


def is_github_ip(request_ip):
    """
    Fetch GitHub's public IP ranges and check if the request_ip is within those ranges.

    Args:
        request_ip (str): The IP address of the incoming request.

    Returns:
        bool: True if the IP is within GitHub's ranges, False otherwise.
    """
    try:
        # Fetch the latest GitHub meta data
        response = requests.get('https://api.github.com/meta', timeout=5)
        response.raise_for_status()

        # Get the list of IP ranges for hooks
        hook_ips = response.json()['hooks']

        # Convert the IP ranges to ip_network objects
        github_ranges = [ip_network(ip) for ip in hook_ips]

        # Convert the request IP to an ip_address object
        ip = ip_address(request_ip)

        # Check if the IP is in any of the GitHub IP ranges
        for network in github_ranges:
            if ip in network:
                return True

        return False

    except requests.RequestException as e:
        # Handle network errors, API errors, etc.
        print(f'Error fetching GitHub IP ranges: {e}')
        return False

    except ValueError as e:
        # Handle invalid IP address format
        print(f'Invalid IP address: {e}')
        return False


def load_secret():
    """Load the secret key from the config file.

    Returns:
        _type_: str
    """
    absolute_path = os.path.dirname(__file__)

    config_path = os.path.join(absolute_path, "../config/update_config.json")

    with open(config_path, 'r') as f:
        config = json.load(f)

    secret = config['SECRET_KEY']

    return secret


def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Args:
        payload_body (bytes): The raw request body.
        secret_token (str): The webhook secret token.
        signature_header (str): The 'X-Hub-Signature-256' header from GitHub.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    if not signature_header:
        return False

    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(expected_signature, signature_header):
        return False

    return True


@update_server.route('/update_server', methods=['POST'])
def update():
    # Extract the client's IP address
    if 'X-Forwarded-For' in request.headers:
        # If behind a proxy, get the original IP
        forwarded_for = request.headers.get('X-Forwarded-For')
        # X-Forwarded-For can be a comma-separated list of IPs
        ip_list = [ip.strip() for ip in forwarded_for.split(',')]
        client_ip = ip_list[0]
    else:
        client_ip = request.remote_addr

    # Check if the IP is from GitHub
    if not is_github_ip(client_ip):
        return jsonify({'msg': 'Request IP does not match GitHub IP ranges'}), 403

    # Header validation
    header_reqs = ["X-GitHub-Event", "X-GitHub-Delivery",
                   "X-Hub-Signature-256"]

    if not all(req in request.headers for req in header_reqs):
        return jsonify({'msg': 'Required headers missing'}), 400  # Bad Request

    # Event type validation
    event = request.headers.get('X-GitHub-Event')

    if event != "push":
        return jsonify({'msg': "Wrong event type"}), 400

    # Signature validation
    secret_key = load_secret()
    if not verify_signature(request.data, secret_key, request.headers.get('X-Hub-Signature-256')):
        return jsonify({'msg': 'Signature verification failed'}), 403

    # Payload validation
    payload = request.get_json()
    if not payload:
        return jsonify({'msg': 'Invalid or missing JSON payload'}), 400

    if payload['ref'] != 'refs/heads/main':
        return jsonify({'msg': 'Not main branch, ignoring'}), 200  # OK

    dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    repo = git.Repo(dir_path)
    origin = repo.remotes.origin

    # Pull the latest changes from the main branch
    pull_info = origin.pull()
    if not pull_info or pull_info[0].flags > 128:
        return jsonify({'msg': "Didn't pull any information from remote."}), 200  # OK

    commit_hash = pull_info[0].commit.hexsha

    return jsonify({'msg': f'Updated server to commit {commit_hash}'}), 200  # OK
