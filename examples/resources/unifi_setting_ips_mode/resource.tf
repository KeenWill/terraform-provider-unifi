# Do not combine with the full setting resource for the same site.
resource "unifi_setting_ips_mode" "example" {
  site     = "default"
  ips_mode = "ips"
}
