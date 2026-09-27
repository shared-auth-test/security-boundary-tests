resource "google_compute_network" "fleet" {
  project                 = var.project_id
  name                    = var.name
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "runtime" {
  project       = var.project_id
  name          = format("%s-runtime", var.name)
  region        = var.region
  network       = google_compute_network.fleet.id
  ip_cidr_range = var.subnet_cidr
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = substr(replace(format("%s-runtime", var.name), "_", "-"), 0, 30)
  display_name = "Scintilla runtime"
}

resource "google_compute_firewall" "runtime_https" {
  project = var.project_id
  name    = format("%s-runtime-https", var.name)
  network = google_compute_network.fleet.name

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  source_ranges = [var.subnet_cidr]
  target_tags   = ["scintilla-runtime"]
}

resource "google_compute_instance" "runtime" {
  count        = var.instance_count
  project      = var.project_id
  name         = format("%s-%d", var.name, count.index + 1)
  zone         = var.zone
  machine_type = var.machine_type
  tags         = ["scintilla-runtime"]

  boot_disk {
    initialize_params { image = var.image }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.runtime.id
  }

  service_account {
    email  = google_service_account.runtime.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "TRUE"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}

resource "google_compute_instance_group" "runtime" {
  project   = var.project_id
  name      = format("%s-runtime", var.name)
  zone      = var.zone
  instances = google_compute_instance.runtime[*].self_link
  named_port {
    name = "https"
    port = 443
  }
}

resource "google_compute_health_check" "runtime" {
  project = var.project_id
  name    = format("%s-runtime", var.name)
  tcp_health_check { port = 443 }
}

resource "google_compute_region_backend_service" "runtime" {
  project               = var.project_id
  name                  = format("%s-runtime", var.name)
  region                = var.region
  protocol              = "TCP"
  load_balancing_scheme = "INTERNAL"
  health_checks         = [google_compute_health_check.runtime.id]
  backend { group = google_compute_instance_group.runtime.id }
}

resource "google_compute_forwarding_rule" "runtime" {
  project               = var.project_id
  name                  = format("%s-runtime", var.name)
  region                = var.region
  network               = google_compute_network.fleet.id
  subnetwork            = google_compute_subnetwork.runtime.id
  load_balancing_scheme = "INTERNAL"
  backend_service       = google_compute_region_backend_service.runtime.id
  ip_protocol           = "TCP"
  ports                 = ["443"]
}

resource "google_dns_record_set" "runtime" {
  count        = var.dns_managed_zone != null && var.dns_name != null ? 1 : 0
  project      = var.project_id
  managed_zone = var.dns_managed_zone
  name         = var.dns_name
  type         = "A"
  ttl          = 60
  rrdatas      = [google_compute_forwarding_rule.runtime.ip_address]
}
