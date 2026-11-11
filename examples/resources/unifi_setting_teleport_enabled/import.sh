#!/usr/bin/env bash
set -euo pipefail

# Replace the illustrative ID with the existing singleton ID for this site.
tofu import unifi_setting_teleport_enabled.example default:teleport-fixture-id
