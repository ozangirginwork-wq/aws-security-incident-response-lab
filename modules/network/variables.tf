variable "project_name" {
  description = "Name prefix for network resources."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR range for the VPC."
  type        = string
}

variable "public_subnet_cidr" {
  description = "CIDR range for the public subnet."
  type        = string
}

variable "private_subnet_cidr" {
  description = "CIDR range for the private subnet."
  type        = string
}

variable "availability_zone" {
  description = "Availability Zone for the lab subnets."
  type        = string
}

variable "allowed_https_cidr" {
  description = "Trusted CIDR allowed to use HTTPS."
  type        = string
}
