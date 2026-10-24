# Open Bastion -- sudo with an SSO token minted at every password prompt (#377)
#
# Under maximum security a deployed host's sudo only takes the single-use
# tokens the portal mints (llng pam_token). This become plugin is the stock
# sudo one, with one difference: it carries no password. When sudo asks for
# one, the connection plugin tells it so (check_password_prompt) and only then
# does it run ansible_become_token_cmd on the controller, and hand sudo what
# the command prints. So the portal mints exactly one token per sudo run, and
# none for a task that needs no root, instead of one per evaluation of
# ansible_become_password, which Ansible templates several times per task,
# prompt or not.
#
# The command runs on the operator's workstation, so no managed host may
# choose it. Its variable is named ansible_become_*: Ansible drops every key
# of that form from the facts a module returns (ansible.vars.clean.clean_facts),
# as it does for ansible_become_exe, where a plain name could be set by a
# compromised host at fact precedence, above group_vars and role defaults.
#
# tasks/main.yml switches a host found locked to this method; the run that
# deploys it keeps the deploy account's own password with the stock sudo.
#
# Assumed of the connection plugin: it calls check_password_prompt before it
# reads get_option('become_pass'), as local and ssh do (ansible-core 2.15 to
# 2.22). Before the prompt that option is a placeholder, never a password. A
# host played with connection: local gives the whole prompt, mint included,
# ansible_local_become_success_timeout (10 s on ansible-core >= 2.19): raise
# it when the portal is slow.
from __future__ import annotations

DOCUMENTATION = """
    name: ob_sudo_sso
    short_description: sudo, with an SSO token minted at each password prompt
    description:
        - Runs the task through sudo as the sudo become plugin does. When sudo
          asks for a password, runs O(token_cmd) on the controller and sends
          what it prints, a single-use SSO token, so each elevation goes
          through the SSO under the name of the person running the play.
          No token is minted for a task that does not become root.
    author: Open Bastion
    options:
        token_cmd:
            description:
                - Command run on the controller, through the shell, at each
                  password prompt of sudo. Its standard output is the token.
                  Typically C(llng --llng-server sso.example.com pam_token).
                  It gets no standard input (a client without a session fails
                  at once rather than waits for a login), is killed after
                  60 seconds, and is named in error messages and at -vvv, so
                  it must hold no secret.
            type: str
            required: true
            vars:
              - name: ansible_become_token_cmd
        become_user:
            description: User you 'become' to execute the task
            default: root
            ini:
              - section: privilege_escalation
                key: become_user
              - section: sudo_become_plugin
                key: user
            vars:
              - name: ansible_become_user
              - name: ansible_sudo_user
            env:
              - name: ANSIBLE_BECOME_USER
              - name: ANSIBLE_SUDO_USER
            keyword:
              - name: become_user
        become_exe:
            description: Sudo executable
            default: sudo
            ini:
              - section: privilege_escalation
                key: become_exe
              - section: sudo_become_plugin
                key: executable
            vars:
              - name: ansible_become_exe
              - name: ansible_sudo_exe
            env:
              - name: ANSIBLE_BECOME_EXE
              - name: ANSIBLE_SUDO_EXE
            keyword:
              - name: become_exe
        become_flags:
            description: Options to pass to sudo
            default: -H -S -n
            ini:
              - section: privilege_escalation
                key: become_flags
              - section: sudo_become_plugin
                key: flags
            vars:
              - name: ansible_become_flags
              - name: ansible_sudo_flags
            env:
              - name: ANSIBLE_BECOME_FLAGS
              - name: ANSIBLE_SUDO_FLAGS
            keyword:
              - name: become_flags
        become_pass:
            description:
                - Ignored. The password is the token O(token_cmd) prints at
                  each prompt. Declared so that the stock sudo logic finds it.
            type: str
            secret: true
            required: false
            vars:
              - name: ansible_become_password
              - name: ansible_become_pass
              - name: ansible_sudo_pass
        sudo_chdir:
            description: Directory to change to before invoking sudo.
            type: str
            required: false
            vars:
              - name: ansible_sudo_chdir
            env:
              - name: ANSIBLE_SUDO_CHDIR
            ini:
              - section: sudo_become_plugin
                key: chdir
"""

import os
import signal
import subprocess

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.become.sudo import BecomeModule as SudoBecomeModule


class BecomeModule(SudoBecomeModule):

    name = 'ob_sudo_sso'

    # What get_option('become_pass') answers before a prompt: truthy, so that
    # the stock logic drops -n and gives sudo Ansible's prompt (-p), and the
    # connection waits for it. Never sent: the connection asks for the
    # password only after check_password_prompt matched, which replaces it.
    _NO_TOKEN_YET = 'sso-token-at-prompt'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._token = None

    def build_become_command(self, cmd, shell):
        # One command, one prompt at most: forget the previous task's token.
        self._token = None
        return super().build_become_command(cmd, shell)

    def get_option(self, option, hostvars=None, playcontext=None):
        if option == 'become_pass':
            return self._token or self._NO_TOKEN_YET
        return super().get_option(option, hostvars=hostvars, playcontext=playcontext)

    def check_password_prompt(self, b_output):
        matched = super().check_password_prompt(b_output)
        if matched and self._token is None:
            self._token = self._mint()
        return matched

    _MINT_TIMEOUT = 60

    def _mint(self):
        cmd = (self.get_option('token_cmd') or '').strip()
        if not cmd:
            raise AnsibleError('ob_sudo_sso: ansible_become_token_cmd is not set')
        # No stdin: a command that would wait for a login (an llng client
        # without a session in its cookie jar) fails at once instead. Its own
        # session, so that the timeout kills what the shell started too. The
        # errors name neither the command line nor the token.
        try:
            p = subprocess.Popen(cmd, shell=True, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True)
        except OSError as e:
            raise AnsibleError('ob_sudo_sso: could not run ansible_become_token_cmd: %s' % e.strerror)
        try:
            out, err = p.communicate(timeout=self._MINT_TIMEOUT)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
            p.communicate()
            raise AnsibleError('ob_sudo_sso: ansible_become_token_cmd gave no token within %d s'
                               % self._MINT_TIMEOUT)
        if p.returncode != 0:
            raise AnsibleError('ob_sudo_sso: ansible_become_token_cmd exited %d: %s'
                               % (p.returncode, to_text(err).strip()))
        token = to_text(out).strip()
        if not token or '\n' in token:
            raise AnsibleError('ob_sudo_sso: ansible_become_token_cmd must print one token, got %d line(s)'
                               % len(token.splitlines()))
        return token
