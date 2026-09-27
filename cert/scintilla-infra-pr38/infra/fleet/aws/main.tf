resource "aws_vpc" "fleet" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  tags                 = { Name = var.name }
}

resource "aws_internet_gateway" "fleet" {
  vpc_id = aws_vpc.fleet.id
  tags   = { Name = var.name }
}

resource "aws_subnet" "runtime" {
  vpc_id                  = aws_vpc.fleet.id
  cidr_block              = var.subnet_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false
  tags                    = { Name = format("%s-runtime", var.name) }
}

resource "aws_route_table" "runtime" {
  vpc_id = aws_vpc.fleet.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.fleet.id
  }
  tags = { Name = format("%s-runtime", var.name) }
}

resource "aws_route_table_association" "runtime" {
  subnet_id      = aws_subnet.runtime.id
  route_table_id = aws_route_table.runtime.id
}

resource "aws_security_group" "runtime" {
  name_prefix = format("%s-runtime-", var.name)
  vpc_id      = aws_vpc.fleet.id

  ingress {
    description = "TLS runtime ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  dynamic "ingress" {
    for_each = length(var.ssh_ingress_cidrs) == 0 ? [] : [1]
    content {
      description = "Operator SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = var.ssh_ingress_cidrs
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_role" "runtime" {
  name_prefix = format("%s-runtime-", var.name)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "runtime" {
  name_prefix = format("%s-runtime-", var.name)
  role        = aws_iam_role.runtime.name
}

resource "aws_instance" "runtime" {
  count                  = var.instance_count
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.runtime.id
  vpc_security_group_ids = [aws_security_group.runtime.id]
  iam_instance_profile   = aws_iam_instance_profile.runtime.name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device { encrypted = true }

  tags = {
    Name = format("%s-%d", var.name, count.index + 1)
    Role = "scintilla-runtime"
  }
}

resource "aws_lb" "runtime" {
  name               = substr(replace(var.name, "_", "-"), 0, 32)
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.runtime.id]
}

resource "aws_lb_target_group" "runtime" {
  name     = substr(format("%s-https", replace(var.name, "_", "-")), 0, 32)
  port     = 443
  protocol = "TCP"
  vpc_id   = aws_vpc.fleet.id
  health_check {
    protocol = "TCP"
    port     = "traffic-port"
  }
}

resource "aws_lb_target_group_attachment" "runtime" {
  count            = var.instance_count
  target_group_arn = aws_lb_target_group.runtime.arn
  target_id        = aws_instance.runtime[count.index].id
  port             = 443
}

resource "aws_lb_listener" "runtime" {
  load_balancer_arn = aws_lb.runtime.arn
  port              = 443
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.runtime.arn
  }
}

resource "aws_route53_record" "runtime" {
  count   = var.route53_zone_id != null && var.dns_name != null ? 1 : 0
  zone_id = var.route53_zone_id
  name    = var.dns_name
  type    = "A"
  alias {
    name                   = aws_lb.runtime.dns_name
    zone_id                = aws_lb.runtime.zone_id
    evaluate_target_health = true
  }
}
