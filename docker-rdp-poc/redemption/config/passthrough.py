#!/usr/bin/env python3
"""
WALLIX Redemption Passthrough Authentication Hook for LemonLDAP::NG

This script is called by Redemption when a user attempts to connect.
It validates the user's authorization via the LLNG /pam/authorize API.

The same pamAccessServerGroups used for SSH apply to RDP connections.

Environment variables:
    LLNG_PORTAL_URL: LemonLDAP::NG portal URL (required)
    LLNG_SERVER_TOKEN: Server Bearer token from enrollment (required)
    DEFAULT_TARGET_HOST: Default RDP target if not specified
    DEFAULT_TARGET_PORT: Default RDP port (default: 3389)

Input (from stdin, JSON):
    {
        "login": "username",
        "password": "user_password",
        "ip_source": "client_ip",
        "target": "target_hostname"  (optional)
    }

Output (to stdout, JSON):
    Success:
    {
        "status": "authorized",
        "target_login": "windows_username",
        "target_password": "windows_password",
        "target_host": "target_hostname",
        "target_port": 3389
    }

    Failure:
    {
        "status": "denied",
        "message": "reason"
    }
"""

import json
import os
import sys
import logging

try:
    import requests
except ImportError as e:
    # Critical dependency missing
    error_output = json.dumps({
        "status": "denied",
        "message": "Internal error: missing requests dependency"
    })
    print(error_output)
    sys.exit(1)

# Configure logging with fallback if file is not writable
LOG_FILE_PATH = '/var/log/rdpproxy/passthrough.log'

handlers = [logging.StreamHandler(sys.stderr)]
try:
    log_dir = os.path.dirname(LOG_FILE_PATH)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    handlers.append(file_handler)
except (OSError, PermissionError):
    # Fall back to stderr-only logging if file is not writable
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=handlers,
)
logger = logging.getLogger('llng-passthrough')


class LLNGAuthenticator:
    """Handles authentication and authorization via LemonLDAP::NG API."""

    def __init__(self):
        self.portal_url = os.environ.get('LLNG_PORTAL_URL')
        self.server_token = os.environ.get('LLNG_SERVER_TOKEN')
        self.server_group = os.environ.get('LLNG_SERVER_GROUP', 'rdp-proxy')
        self.default_target = os.environ.get('DEFAULT_TARGET_HOST')
        self.default_port = int(os.environ.get('DEFAULT_TARGET_PORT', '3389'))
        self.timeout = int(os.environ.get('LLNG_TIMEOUT', '10'))

        if not self.portal_url:
            raise ValueError("LLNG_PORTAL_URL environment variable is required")
        if not self.server_token:
            raise ValueError("LLNG_SERVER_TOKEN environment variable is required")

    def authorize(self, user: str, target_host: str, client_ip: str) -> dict:
        """
        Check if user is authorized to access the target RDP server.

        Uses the existing /pam/authorize endpoint with service=rdp.
        This means the same pamAccessServerGroups apply to RDP as SSH.

        Args:
            user: Username attempting to connect
            target_host: Target RDP server hostname
            client_ip: Client's source IP address

        Returns:
            dict with 'authorized' boolean and optional 'message'
        """
        url = f"{self.portal_url}/pam/authorize"

        headers = {
            'Authorization': f'Bearer {self.server_token}',
            'Content-Type': 'application/json',
        }

        payload = {
            'user': user,
            'host': target_host,
            'service': 'rdp',  # New service type for RDP
            'server_group': self.server_group,
            'client_ip': client_ip,
        }

        try:
            logger.info(f"Checking authorization for user={user}, target={target_host}")

            response = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"Authorization result for {user}: {result.get('authorized')}")
                return result

            elif response.status_code == 401:
                logger.warning(f"Server token invalid or expired")
                return {'authorized': False, 'message': 'Server authentication failed'}

            elif response.status_code == 403:
                logger.info(f"User {user} not authorized for {target_host}")
                return {'authorized': False, 'message': 'Access denied'}

            else:
                logger.error(f"LLNG API error: {response.status_code} - {response.text}")
                return {'authorized': False, 'message': f'API error: {response.status_code}'}

        except requests.exceptions.Timeout:
            logger.error(f"Timeout connecting to LLNG portal")
            return {'authorized': False, 'message': 'Authentication service timeout'}

        except requests.exceptions.RequestException as e:
            logger.error(f"Error connecting to LLNG: {e}")
            return {'authorized': False, 'message': 'Authentication service unavailable'}


def read_input() -> dict:
    """Read JSON input from Redemption via stdin."""
    try:
        input_data = sys.stdin.read()
        # Note: Do not log input_data as it contains passwords
        return json.loads(input_data)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON input: {e}")
        return {}


def write_output(result: dict) -> None:
    """Write JSON output for Redemption to stdout."""
    # Note: Do not log result as it may contain passwords
    print(json.dumps(result, ensure_ascii=True))


def main():
    """Main passthrough authentication handler."""

    # Read input from Redemption
    input_data = read_input()

    if not input_data:
        write_output({
            'status': 'denied',
            'message': 'Invalid input'
        })
        return 1

    # Extract connection details
    login = input_data.get('login', '')
    password = input_data.get('password', '')
    client_ip = input_data.get('ip_source', 'unknown')
    target = input_data.get('target', '')

    if not login:
        logger.warning("No login provided")
        write_output({
            'status': 'denied',
            'message': 'Username required'
        })
        return 1

    try:
        auth = LLNGAuthenticator()
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        write_output({
            'status': 'denied',
            'message': 'Server configuration error'
        })
        return 1

    # Use default target if not specified
    target_host = target or auth.default_target
    if not target_host:
        logger.warning("No target host specified and no default configured")
        write_output({
            'status': 'denied',
            'message': 'Target host required'
        })
        return 1

    # Check authorization with LLNG
    auth_result = auth.authorize(login, target_host, client_ip)

    if auth_result.get('authorized'):
        # User is authorized - pass credentials through to target
        # In a production environment, you might:
        # - Look up credentials from a vault
        # - Transform username (e.g., add domain)
        # - Use certificate-based auth

        # For PoC: pass-through mode (user provides their Windows credentials)
        target_login = input_data.get('target_login', login)
        target_password = input_data.get('target_password', password)

        # Log successful authorization
        logger.info(
            f"Authorized: user={login}, target={target_host}, "
            f"client_ip={client_ip}"
        )

        write_output({
            'status': 'authorized',
            'target_login': target_login,
            'target_password': target_password,
            'target_host': target_host,
            'target_port': auth.default_port,
        })
        return 0

    else:
        # User not authorized
        message = auth_result.get('message', 'Access denied')
        logger.warning(
            f"Denied: user={login}, target={target_host}, "
            f"client_ip={client_ip}, reason={message}"
        )

        write_output({
            'status': 'denied',
            'message': message
        })
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        logger.exception(f"Unhandled exception: {e}")
        write_output({
            'status': 'denied',
            'message': 'Internal error'
        })
        sys.exit(1)
