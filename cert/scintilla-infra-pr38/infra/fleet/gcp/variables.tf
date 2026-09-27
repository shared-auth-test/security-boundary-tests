variable "project_id" { type = string }
variable "name" { type = string }
variable "region" { type = string }
variable "zone" { type = string }
variable "subnet_cidr" { type = string }
variable "image" {
  type        = string
  description = "Reviewed NixOS image self-link or family reference."
}
variable "machine_type" {
  type    = string
  default = "c3-standard-4"
}
variable "instance_count" {
  type    = number
  default = 3
  validation {
    condition     = var.instance_count >= 3 && var.instance_count <= 9
    error_message = "Bare-process fleets support 3 through 9 nodes."
  }
}
variable "dns_managed_zone" {
  type    = string
  default = null
}
variable "dns_name" {
  type    = string
  default = null
}
