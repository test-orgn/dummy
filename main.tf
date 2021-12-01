provider "aws" {
  region  = var.aws_region
  version = "~> 2.0"
}

terraform {
  backend "s3" {}
}

variable "datadog_api_key" {}
variable "aws_region" {}
variable "environment" {}
variable "ecs_cluster" {}
variable "vpc_id" {}
variable "load_balancer" {}
variable "load_balancer_https_listener" {}
variable "service_listener_rule_path" {}
variable "health_check_path" {}
variable "service_name" {}
variable "service_listener_rule_priority" {}
variable "image_repository" {}
variable "build_version" {}
variable "container_port" { type = number }
variable "desired_task_count" {}
variable "task_memory_soft_limit" { type = number }
variable "container_type" {}
variable "subnet_type" {}
variable "DB_HOST_DISCOVERY" {}
variable "jfrog_secret_manager" {
    type = string
    default = "false"
}
variable "fargate_deploy" {
    type = string
    default = "false"
}
variable "cpu" {
    default = 256
}
variable "apm_id_tag" {}
variable "business_segment_tag" {}
variable "business_tower_tag" {}
variable "environment_tag" {}
variable "service_tag" {}
variable "support_group_tag" {}
variable "billing_approver_tag" {}
variable "fmc_tag" {}
variable "APP_BASE_URL" {}
variable "APP_BACKEND_URL" {}
variable "APP_CORS_URL" {}
variable "DB_HOST" {}
variable "DB_USER" {}
variable "DB_PASSWORD" {}
variable "AUTH_GITHUB_CLIENT_ID" {}
variable "AUTH_GITHUB_CLIENT_SECRET" {}
variable "AUTH_MICROSOFT_CLIENT_ID" {}
variable "AUTH_MICROSOFT_CLIENT_SECRET" {}
variable "AUTH_MICROSOFT_TENANT_ID" {}
variable "GITHUB_TOKEN" {}

variable "service_name_email" {}
variable "build_version_email" {}
variable "container_port_email" {}
variable "image_repository_email" {}
variable "email_service_pwd" {}
#variable "email_service_url" {}
variable "email_service_user_name" {}
variable "api_ado_auth_token" {}
variable "api_ado_auth_user_name" {}
variable "api_github_base_url" {}
variable "api_github_pwd" {}
variable "api_github_user_name" {}
variable "api_github_webhook_private_key" {}
variable "api_github_webhook_pwd" {}
variable "api_github_webhook_user_id" {}
variable "api_WSo2_base_url" {}
variable "api_WSo2_client_id" {}
variable "api_WSo2_client_secret" {}
variable "aws_access_key" {}
variable "aws_delay" {}
variable "aws_s3_bucket_name" {}
variable "aws_secret_key" {}
variable "cornexpression_ado" {}
variable "cornexpression_wso2" {}
variable "devx_base_url" {}
variable "scheduler_ado_isactive" {}
variable "scheduler_wso2_isactive" {}
variable "vault_approle_id" {}
variable "vault_approle_secret" {}
locals {
    fargate_deploy = var.fargate_deploy == "true" ? true : false
    environment = var.environment_tag
    containers = {
        standard = data.template_file.container_definition_standard.rendered
        standard_jfrog = data.template_file.container_definition_jfrog.rendered
        spring_jfrog = data.template_file.container_definition_spring_jfrog.rendered
        discovery_api=data.template_file.container_definition_discovery.rendered
    }
    subnets = {
      
    }
    tags = {
        ApmID           = var.apm_id_tag
        BillingApprover = var.billing_approver_tag
        BusinessTower   = var.business_tower_tag
        BusinessSegment = var.business_segment_tag
        Environment     = var.environment_tag
        FMC             = var.fmc_tag
        Service         = var.service_tag
        SupportGroup    = var.support_group_tag
    }
}

data "template_file" "container_definition_standard" {
  template = file("container_definition.json.tpl")

  vars = {
    service_name = var.service_name
    image_repository = var.image_repository
    build_version = var.build_version
    task_memory_soft_limit = var.task_memory_soft_limit
    environment = var.environment
    container_port = var.container_port
    host_port = local.fargate_deploy ? var.container_port : 0
    aws_region = var.aws_region
    stream_prefix = var.build_version
  }
}

data "template_file" "container_definition_jfrog" {
  template = file("container_definition_jfrog.json.tpl")

  vars = {
    service_name = var.service_name
    image_repository = var.image_repository
    build_version = var.build_version
    task_memory_soft_limit = var.task_memory_soft_limit
    environment = var.environment
    container_port = var.container_port
    host_port = local.fargate_deploy ? var.container_port : 0
    aws_region = var.aws_region
    stream_prefix = var.build_version
    jfrog_secret_manager = var.jfrog_secret_manager
  }
}

data "template_file" "container_definition_spring_jfrog" {
    template = file("container_definition_spring_jfrog.json.tpl")

    vars = {
        service_name = var.service_name
        image_repository = var.image_repository
        build_version = var.build_version
        task_memory_soft_limit = var.task_memory_soft_limit
        spring_profile = var.environment
        container_port = var.container_port
        host_port = local.fargate_deploy ? var.container_port : 0
        aws_region = var.aws_region
        stream_prefix = var.build_version
        jfrog_secret_manager = var.jfrog_secret_manager
        GITHUB_TOKEN = var.GITHUB_TOKEN
        APP_BASE_URL =var.APP_BASE_URL
        APP_BACKEND_URL =var.APP_BACKEND_URL
        APP_CORS_URL =var.APP_CORS_URL
        DB_HOST =var.DB_HOST
        DB_USER =var.DB_USER
        DB_PASSWORD =var.DB_PASSWORD
        AUTH_GITHUB_CLIENT_ID =var.AUTH_GITHUB_CLIENT_ID
        AUTH_GITHUB_CLIENT_SECRET =var.AUTH_GITHUB_CLIENT_SECRET
        AUTH_MICROSOFT_CLIENT_ID =var.AUTH_MICROSOFT_CLIENT_ID
        AUTH_MICROSOFT_CLIENT_SECRET =var.AUTH_MICROSOFT_CLIENT_SECRET
        AUTH_MICROSOFT_TENANT_ID =var.AUTH_MICROSOFT_TENANT_ID

    }
}

data "template_file" "container_definition_discovery" {
    template = file("container_definition_discovery.json.tpl")

    vars = {
        datadog_api_key=var.datadog_api_key
        vault_approle_secret=var.vault_approle_secret
        vault_approle_id=var.vault_approle_id
        service_name_email = var.service_name_email
        image_repository_email = var.image_repository_email
        build_version_email = var.build_version_email
        container_port_email = var.container_port_email
        host_port_email = local.fargate_deploy ? var.container_port_email : 0
        service_name = var.service_name
        image_repository = var.image_repository
        build_version = var.build_version
        task_memory_soft_limit = var.task_memory_soft_limit
        spring_profile = var.environment
        container_port = var.container_port
        host_port = local.fargate_deploy ? var.container_port : 0
        aws_region = var.aws_region
        stream_prefix = var.build_version
        jfrog_secret_manager = var.jfrog_secret_manager
        DB_HOST_DISCOVERY =var.DB_HOST_DISCOVERY
        DB_USER =var.DB_USER
        DB_PASSWORD =var.DB_PASSWORD
        api_ado_auth_token=var.api_ado_auth_token
        api_ado_auth_user_name=var.api_ado_auth_user_name
        api_github_base_url = var.api_github_base_url
        api_github_pwd = var.api_github_pwd
        api_github_user_name = var.api_github_user_name
        api_github_webhook_private_key = var.api_github_webhook_private_key
        api_github_webhook_pwd = var.api_github_webhook_pwd
        api_github_webhook_user_id = var.api_github_webhook_user_id
        api_WSo2_base_url = var.api_WSo2_base_url
        api_WSo2_client_id = var.api_WSo2_client_id
        api_WSo2_client_secret = var.api_WSo2_client_secret
        aws_access_key = var.aws_access_key
        aws_delay = var.aws_delay
        aws_s3_bucket_name = var.aws_s3_bucket_name
        aws_secret_key = var.aws_secret_key
        cornexpression_ado = var.cornexpression_ado
        cornexpression_wso2 = var.cornexpression_wso2
        devx_base_url = var.devx_base_url
        scheduler_ado_isactive = var.scheduler_ado_isactive
        scheduler_wso2_isactive = var.scheduler_wso2_isactive
        GITHUB_TOKEN = var.GITHUB_TOKEN
        email_service_user_name =var.email_service_user_name
        email_service_pwd =var.email_service_pwd

    }
}


data "aws_iam_policy" "ecs_task_execution_role" {
    }

resource "aws_iam_role" "service_execution_role_fargate" {
    count = local.fargate_deploy ? 1 : 0
    name = format("%s-%s-%s", "ecs-task-service-execution", var.service_name, var.environment)

    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": [ "ecs-tasks.amazonaws.com" ] },
            "Action": [ "sts:AssumeRole" ]
        }
    ]
}
EOF
}

resource "aws_iam_role" "task_role_fargate" {
    count = local.fargate_deploy ? 1 : 0
    name = format("%s-%s-%s", "ecs-task-service-role", var.service_name, var.environment)

    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": [ "ecs-tasks.amazonaws.com" ] },
            "Action": [ "sts:AssumeRole" ]
        }
    ]
}
EOF
}

resource "aws_iam_role" "service_role_ec2" {
    count = local.fargate_deploy ? 0 : 1
    name = format("%s-%s-%s", "ecs-service", var.service_name, var.environment)

    assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": [ 
                "ecs.amazonaws.com" ,
                "ecs-tasks.amazonaws.com"
                 ] },
            "Action": [ "sts:AssumeRole" ]
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "task_role_policy" {
    count = local.fargate_deploy ? 1 : 0 
    name = format("%s-%s-%s", "ecs-service", var.service_name, var.environment)
    role = aws_iam_role.task_role_fargate[0].id

    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:Describe*",
                "secretsmanager:Get*",
                "secretsmanager:List*",
                "dynamodb:BatchGetItem",
                "dynamodb:DescribeTable",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:Query",
                "dynamodb:Scan",
                "dynamodb:BatchWriteItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
                "dynamodb:ListTables",
                "dynamodb:ConditionCheckItem",
                "s3:*",
                "sqs:*",
                "sns:*",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams" 
            ],
            "Resource": "*"
        }
    ]
}
EOF
}
resource "aws_iam_role_policy" "task_role_policy_cloudlog" {
    count = local.fargate_deploy ? 1 : 0     
    name = format("%s-%s-%s", "ecs-service", var.service_name, var.environment)
    role = aws_iam_role.service_execution_role_fargate[0].id

    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:Describe*",
                "secretsmanager:Get*",
                "secretsmanager:List*",                
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "task_s3" {
    count = local.fargate_deploy ? 1 : 0
  role       = "${aws_iam_role.task_role_fargate[0].name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
resource "aws_iam_role_policy_attachment" "task_s3_fargate" {
    count = local.fargate_deploy ? 1 : 0
  role       = "${aws_iam_role.service_execution_role_fargate[0].name}"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}



resource "aws_iam_role_policy_attachment" "ecs-task-execution-role-policy-attachment-fargate" {
  role       = aws_iam_role.service_execution_role_fargate[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}


resource "aws_iam_role_policy" "service_role_policy" {
    count = local.fargate_deploy ? 0 : 1 
    name = format("%s-%s-%s", "ecs-service", var.service_name, var.environment)
    role = aws_iam_role.service_role_ec2[0].id

    policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AuthorizeSecurityGroupIngress",
                "ec2:Describe*",
                "ec2:AttachNetworkInterface",
                "ec2:CreateNetworkInterface",
                "ec2:CreateNetworkInterfacePermission",
                "ec2:DeleteNetworkInterface",
                "ec2:DeleteNetworkInterfacePermission",
                "ec2:DetachNetworkInterface",                
                "elasticloadbalancing:DeregisterInstancesFromLoadBalancer",
                "elasticloadbalancing:Describe*",
                "elasticloadbalancing:RegisterInstancesWithLoadBalancer",
                "elasticloadbalancing:DeregisterTargets",
                "elasticloadbalancing:DescribeTargetGroups",
                "elasticloadbalancing:DescribeTargetHealth",
                "elasticloadbalancing:RegisterTargets"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role" {
    role = local.fargate_deploy ? aws_iam_role.service_execution_role_fargate[0].name : aws_iam_role.service_role_ec2[0].name
    policy_arn = data.aws_iam_policy.ecs_task_execution_role.arn
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution_role_secret" {
    role = local.fargate_deploy ? aws_iam_role.service_execution_role_fargate[0].name : aws_iam_role.service_role_ec2[0].name
    policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

resource "aws_lb_target_group" "service_target_group" {
    name = format("%s-%s-%s", var.service_name, substr(var.environment, 0, 3), "SvcTG")
    vpc_id = var.vpc_id
    port = 80
    protocol = "HTTP"
    deregistration_delay = 0
    target_type = local.fargate_deploy ? "ip" : "instance"

    health_check {
        enabled = true
        interval = 240
        path = var.health_check_path
        protocol = "HTTP"
        timeout = 60
        healthy_threshold = 5
        unhealthy_threshold = 2
    }
    
    tags = local.tags
}

resource "aws_lb_listener_rule" "service_listener_rule" {
    listener_arn = var.load_balancer_https_listener
    priority = var.service_listener_rule_priority
      condition {
        path_pattern {
            values = [ var.service_listener_rule_path ]
        }
    }
    action {
        type = "forward"
        target_group_arn = aws_lb_target_group.service_target_group.arn
    }
    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_lb_listener_rule" "service_listener_rule_header" {
    listener_arn = var.load_balancer_https_listener
    priority = 3
    condition {
    http_header {
      http_header_name = "X-GitHub-Hook-Installation-Target-Type"
      values           = ["organization"]
    }
  }
    
   
    action {
        type = "forward"
        target_group_arn = aws_lb_target_group.service_target_group.arn
    }
    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_ecs_task_definition" "service_task_definition_fargate" {
    count = local.fargate_deploy ? 1 : 0
    family = var.service_name
    memory = var.task_memory_soft_limit
    cpu = var.cpu
    container_definitions = lookup(local.containers, var.container_type, data.template_file.container_definition_standard.rendered)
    requires_compatibilities = ["FARGATE"]
    network_mode = "awsvpc"
    execution_role_arn = aws_iam_role.service_execution_role_fargate[0].arn
    task_role_arn = aws_iam_role.task_role_fargate[0].arn

    lifecycle {
        create_before_destroy = true
    }

    tags = local.tags
}

resource "aws_ecs_task_definition" "service_task_definition_ec2" {
    count = local.fargate_deploy ? 0 : 1
    family = var.service_name
    container_definitions = lookup(local.containers, var.container_type, data.template_file.container_definition_standard.rendered)
    execution_role_arn = aws_iam_role.service_role_ec2[count.index].arn
    lifecycle {
        create_before_destroy = true
    }

    tags = local.tags
}

resource "aws_ecs_service" "service_fargate" {
    depends_on=[aws_security_group.ecs_service_sg]
    count = local.fargate_deploy ? 1 : 0
    name = format("%s-%s", var.service_name, var.environment)
    cluster = var.ecs_cluster
    task_definition = "${aws_ecs_task_definition.service_task_definition_fargate[0].family}:${aws_ecs_task_definition.service_task_definition_fargate[0].revision}"
    deployment_minimum_healthy_percent = 100
    deployment_maximum_percent = 200
    desired_count = var.desired_task_count
    launch_type = "FARGATE"
    propagate_tags = "TASK_DEFINITION"
    
    network_configuration {
      subnets = lookup(local.subnets, var.subnet_type, local.subnets["nonprod-private"])
      security_groups =   ["${aws_security_group.ecs_service_sg.id}"]    
      assign_public_ip=false
    }

    load_balancer {
        target_group_arn = aws_lb_target_group.service_target_group.arn
        container_name = var.service_name
        container_port = var.container_port
    }

    tags = local.tags
}

resource "aws_security_group" "ecs_service_sg" {
  name        = "${var.service_name}-sg-${var.environment}"
  description = "Allow access to ECS services for ${var.service_name}"
  vpc_id      = var.vpc_id  
  ingress {
    from_port   =var.container_port
    to_port     = var.container_port
    protocol    = "tcp"
    description = "Allow any "
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    description = "Allow any "
    cidr_blocks = ["0.0.0.0/0"]
  }
  

  tags = merge({ "Name" = "${var.service_name}-sg" }, local.tags)
}


resource "aws_ecs_service" "service_ec2" {
    count = local.fargate_deploy ? 0 : 1
    name = format("%s-%s", var.service_name, var.environment)
    cluster = var.ecs_cluster
    task_definition = "${aws_ecs_task_definition.service_task_definition_ec2[0].family}:${aws_ecs_task_definition.service_task_definition_ec2[0].revision}"
    desired_count = var.desired_task_count
    iam_role = aws_iam_role.service_role_ec2[0].arn
    deployment_minimum_healthy_percent = 100
    deployment_maximum_percent = 200
    launch_type = "EC2"
    propagate_tags = "TASK_DEFINITION"
    depends_on = [aws_iam_role_policy.service_role_policy]

    load_balancer {
        target_group_arn = aws_lb_target_group.service_target_group.arn
        container_name = var.service_name
        container_port = var.container_port
    }

    tags = local.tags
}
