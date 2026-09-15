# Security Policy

## Supported version

Only the latest commit on `main` is maintained.

## Intended use

This repository is an educational defensive-security investigation lab. It is
not a production SIEM or incident-response platform. Published samples are
synthetic; real Windows event exports can contain sensitive host and user data.

## Reporting a security issue

Use GitHub private vulnerability reporting when available. Do not include real
credentials, event exports, usernames, hostnames, or command histories in a
public issue. Revoke and rotate exposed secrets before repository cleanup.

## Maintainer checks

Before publishing, run `pre-commit run --all-files`, the documented test suite,
and GitHub secret scanning. Confirm that `.private/` evidence remains ignored.
