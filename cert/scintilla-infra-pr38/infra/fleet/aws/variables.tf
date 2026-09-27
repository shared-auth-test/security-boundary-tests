variable "name" { type = string }
variable "vpc_cidr" { type = string }
variable "subnet_cidr" { type = string }
variable "availability_zone" { type = string }
variable "ami_id" {
  type        = string
  description = "Reviewed NixOS AMI ID."
}
variable "instance_type" {
  type    = string
  default = "c7i.large"
}
variable "instance_count" {
  type    = number
  default = 3
  validation {
    condition     = var.instance_count >= 3 && var.instance_count <= 9
    error_message = "Bare-process fleets support 3 through 9 nodes."
  }
}
variable "ssh_ingress_cidrs" {
  type    = list(string)
  default = []
}
variable "route53_zone_id" {
  type    = string
  default = null
}
variable "dns_name" {
  type    = string
  default = null
}
