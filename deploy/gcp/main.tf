# Kronagent GCP Workload Identity Federation Onboarding Module
# Provisions zero-key cross-account IAM Service Accounts and Workload Identity Pool bindings.

variable "project_id" {
  type        = string
  description = "The target GCP Project ID to defend."
}

variable "external_id" {
  type        = string
  description = "Per-tenant external ID for Workload Identity Federation."
}

resource "google_service_account" "kronagent_observe" {
  account_id   = "kronagent-observe"
  display_name = "Kronagent Read-Only Observe Agent"
  project      = var.project_id
}

resource "google_project_iam_member" "observe_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.kronagent_observe.email}"
}

output "observe_service_account" {
  value = google_service_account.kronagent_observe.email
}
