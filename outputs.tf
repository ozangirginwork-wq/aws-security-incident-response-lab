output "vpc_id" {
  description = "ID of the lab VPC."
  value       = module.network.vpc_id
}

output "public_subnet_id" {
  description = "ID of the public subnet."
  value       = module.network.public_subnet_id
}

output "private_subnet_id" {
  description = "ID of the isolated private subnet."
  value       = module.network.private_subnet_id
}

output "web_security_group_id" {
  description = "ID of the restricted web security group."
  value       = module.network.web_security_group_id
}

output "application_security_group_id" {
  description = "ID of the application security group."
  value       = module.network.application_security_group_id
}
