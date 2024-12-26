packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.0.0, <2.0.0"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# can have a default value
variable "source_ami" {
  type    = string
  default = "ami-0866a3c8686eaeeba" # Ubuntu 24.04 LTS image us-east-1
}

# can have a default value
variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

# can have a default value
variable "subnet_id" {
  type    = string
  default = "subnet-01042f3aa69098782" # picked from default vpc subnet us-east-1a
}

variable "instance_type" {
  type    = string
  default = "t2.micro"
}

variable "ami_devicename" {
  type    = string
  default = "/dev/sda1"
}

variable "ami_volume_size" {
  type    = number
  default = 8
}

variable "ami_volume_type" {
  type    = string
  default = "gp2"
}

source "amazon-ebs" "my-ami" {
  region          = "${var.aws_region}"
  source_ami      = "${var.source_ami}"
  instance_type   = "${var.instance_type}"
  ssh_username    = "${var.ssh_username}"
  subnet_id       = "${var.subnet_id}"
  ami_name        = "csye6225_webapp_${formatdate("YYYY_MM_DD_HH_mm_ss", timestamp())}"
  ami_description = "CSYE6225 Webapp AMI Assignment-4"

  launch_block_device_mappings {
    device_name           = "${var.ami_devicename}"
    volume_size           = "${var.ami_volume_size}"
    volume_type           = "${var.ami_volume_type}"
    delete_on_termination = true
  }

}

build {
  sources = ["source.amazon-ebs.my-ami"]

  provisioner "file" {
    source      = "../webapp.zip"
    destination = "/tmp/webapp.zip"
  }

  provisioner "shell" {
    script = "webapp_setup.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get remove -y git",
      "sudo apt-get autoremove -y",
      "sudo apt-get clean",
      "sudo rm -rf /usr/bin/git*",
      "sudo rm -rf /usr/lib/git-core"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y wget",

      # Download and install the CloudWatch Agent
      "wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb",
      "sudo dpkg -i -E ./amazon-cloudwatch-agent.deb",

      # Enable CloudWatch Agent to start on boot
      "sudo systemctl enable amazon-cloudwatch-agent",

      # Clean up installation files
      "rm -f amazon-cloudwatch-agent.deb"
    ]
  }
}

