# Requires an Integration API key. Obtain these UUIDs from the official API;
# legacy IDs and provider site names are not interchangeable.
resource "unifi_firewall_policy_flow_reporting" "example" {
  site_id   = "11111111-1111-4111-8111-111111111111"
  policy_id = "22222222-2222-4222-8222-222222222222"
  enabled   = true
}
