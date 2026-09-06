# INTENTIONALLY INSECURE TRAINING FIXTURE — DO NOT DEPLOY.
# Checkov should report unrestricted SSH ingress for this resource.
resource "aws_security_group" "public_ssh" {
  name        = "intentionally-insecure-public-ssh"
  description = "Training fixture: SSH exposed to the internet"
  vpc_id      = "vpc-00000000000000000"

  ingress {
    description = "INSECURE: SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
