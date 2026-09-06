variable "aws_region" {
  description = "AWS Region used for the lab."
  type        = string
  default     = "us-east-1"
}

variable "availability_zone" {
  description = "Availability Zone for the two lab subnets."
  type        = string
  default     = "us-east-1a"
}

variable "project_name" {
  description = "Name applied to project resources."
  type        = string
  default     = "aws-security-operations-lab"
}

variable "vpc_cidr" {
  description = "CIDR range for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR range for the public subnet."
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR range for the private subnet."
  type        = string
  default     = "10.0.2.0/24"
}

variable "allowed_https_cidr" {
  description = "CIDR allowed to reach HTTPS. Replace with a trusted source for deployment."
  type        = string
  default     = "203.0.113.10/32"

  validation {
    condition     = can(cidrnetmask(var.allowed_https_cidr)) && var.allowed_https_cidr != "0.0.0.0/0"
    error_message = "allowed_https_cidr must be a valid, restricted CIDR and cannot be 0.0.0.0/0."
  }
}
