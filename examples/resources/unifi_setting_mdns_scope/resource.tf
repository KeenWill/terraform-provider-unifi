resource "unifi_setting_mdns_scope" "selected_networks" {
  scope       = "some"
  network_ids = [unifi_network.lan.id, unifi_network.iot.id]
}
