# AGENT.md

Read this first. Follow it exactly. Skipping steps will break CI,
block merges, corrupt the codebase or make the maintainers unhappy.

## Presentation

* The goal of Open Bastion is to provide centralized SSH and ``sudo``
  access control to Linux servers with SSO integration.

* The code base is composite implementing a PAM module, an NSS module,
  systemd units, a configuration script `ob-bastion-setup`, and
  deployment helpers targeting shell users and Ansible.

* The toolchain is based on CMake.

* A test suite is integrated to the toolchain.

* Packaging is provided in DEB and RPM format.

## Code comments

- Comment only unconventional or tricky code: a non-obvious
  constraint, a workaround, a subtle ordering, a security-relevant
  detail.
- Never paraphrase the code. If the comment restates what the next
  lines do, delete it.
- No project history in comments: no "used to", "since 0.6", "replaced
  the cron jobs". Exception: rare cases where the history is required
  to understand why the implementation looks the way it does.
- No design rationale in build files, packaging scripts or config
  files.  Link to the relevant documentation instead, if anything.
- When you change code, update or remove the comments around it. An
  obsolete comment is worse than no comment: it misleads reviewers,
  auditors and agents.

## Documentation

- Document architecture choices and feature implementation once, in
  reStructuredText, in the project documentation within the `doc`
  folder.
- Record significant decisions as a short architecture decision record
  in a single place; do not duplicate them in comments, changelog or
  commits.
- Elsewhere, reference that document rather than repeating its content.
- Executable exposed to end-users and administrators are documented in
  man pages, see the `man` folder. Its the right place to document
  command line options.

## Specific files

### CHANGELOG.md

- Audience: administrators operating Open Bastion.
- List user-visible changes only: new features, behaviour changes,
  removals, fixes, security notes.
- The `Unreleased` section describes the difference with the last
  release, not the intermediate steps taken during
  development. Rewrite entries rather than appending corrections.
- Keep entries short; link to the documentation for details.

### UPGRADE-NOTES.md

- Audience: administrators upgrading between released versions.
- State only the actions required and their observable effects.

## Git commit messages

- Audience: developers.
- A concise subject line, then a short body explaining why when it is
  not obvious. Not a diary, not a copy of the documentation.
- Reference issues/PRs here — this is where history belongs.

## Before submitting

- [ ] Every comment explains something non-obvious and still true.
- [ ] No history, issue numbers or rationale in comments or build
      files.
- [ ] Design changes are documented once, in ReST.
- [ ] CHANGELOG entries are written for administrators and reflect the
      current state.
- [ ] Commit messages are concise and explain why.
