# Do not combine with the full setting resource for the same site.
resource "unifi_setting_teleport_enabled" "example" {
  site    = "default"
  enabled = false
}
