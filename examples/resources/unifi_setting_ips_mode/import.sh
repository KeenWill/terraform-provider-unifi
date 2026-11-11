#!/usr/bin/env bash
set -euo pipefail

# Replace the illustrative ID with the existing singleton ID for this site.
tofu import unifi_setting_ips_mode.example default:ips-fixture-id
