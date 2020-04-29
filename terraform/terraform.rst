.. title:: Terraform Leveraging

.. _terraform:

--------------------
Terraform Leveraging
--------------------

Using Terraform to allow Calm to support Alicloud
+++++++++++++++++++++++++++++++++++++++++++++++++

Overview
--------

- Using **Terraform** to focus on IAC (Infrastructure as a Code)
- Using **Calm** to focus on application deployment, and Day 2 operations
- Download blueprints you want to try:

    - :download:`Alicloud ECS with TF <https://github.com/panlm/NTNX/raw/master/calm/blueprints/Terraform-Alicloud.json>`
    - :download:`AWS EC2 with TF <https://github.com/panlm/NTNX/raw/master/calm/blueprints/Terraform-AWS.json>`

- Upload blueprints to Calm
    - You will be prompted to input the **passphrase**, please use **nutanix/4u**.
    - Maybe you need setup the **template** and **network** for Terraform VM
    - Save it and ready to launch

Blueprint
---------

- **Service 1**: New VM

    - New a Service, **Cloud** is **Nutanix**

        .. figure:: images/terr1.png

    - You can assign 1 vcpu / 1 GB memory to this VM
    - Execute `terraform` command on this VM and create ECS instances on Alicloud. Get the public IP of the new instance.

- **Service 2**: Existed VM

    - New a Service, **Cloud** is **Existing Machine**
    - Get the IP addresses from previous services `@@{Terraform.ecs_pub_ip[calm_array_index]}@@`

        .. figure:: images/terr2.png

Launch It
---------

- If you need to create multi ECS instances on Alicloud, just assign variable **num** before you launch blueprint.
- If you launch successfully, you will see the public IP of Alicloud ECS.

    .. figure:: images/terr3.png

.. raw:: html

    <strong><font color="red">After you demo, please remeber to DELETE the applications for COST SAVING</font></strong>

How to access ECS VMs
---------------------

- Expand and click any Alicloud services
- Click **Open Terminal** for this service
- Enjoy your ECS instances.

Terraform Deep Dive 
-------------------

- Click **Open Termianl** to open the console of **Terraform VM**, using **terraform** credential to login

    .. figure:: images/terr4.png

    - Or use this :ref:`ssh_key_priv` to login **Terraform VM** with username **centos**

- You will find one folder named with **number**. In this screenshot, we have folder named **8931**. Remeber to execute **terraform** CLI in this folder

    .. figure:: images/terr5.png

- I have save key information for you. 

    .. figure:: images/terrinfo0.png

    - file **ecs_pub_ip** has all public ip addresses of ECS you have built

        .. figure:: images/terrinfo1.png

    - file **privatekey-tfkey-8931** has private key, you could use it to connect to your ECS instances

    - file **key_name** has the name of the key. you will need it when you run **terraform** CLI

        .. figure:: images/terrinfo2.png

    - Also you could get these info with

        .. code-block:: bash

            terraform output publicip
            terraform output privatekey

- Try to connect to ECS instance

    .. figure:: images/terrinfo3.png

- Enjoy your ECS instances.

Check out how easy Terraform is to integrate with Calm!
+++++++++++++++++++++++++++++++++++++++++++++++++++++++

Prerequisite
------------

- You should have a basic understanding of services provided by public clouds.

    - For AWS, you should know IAM, EC2, etc. 
    - For Alicloud, you should know RAM, ECS, etc.

- You should have public-cloud privider accounts (AWS or Alicloud) for this lab with **Programmatic access** enabled.
- You should be a fan of **CLI** (just kidding!)

3-steps to deploy AWS EC2 with Terraform
----------------------------------------

#. Install **terraform** on your Laptop. (This is Macbook example, for more OS, check the link `HERE <https://www.terraform.io/downloads.html>`_)

    - Download the binaries for your OS, for example: :download:`MacOS 64-bit <https://releases.hashicorp.com/terraform/0.12.10/terraform_0.12.10_darwin_amd64.zip>`
    - Unzip it
    - Move **terraform** to your **/usr/local/bin/**
    - try to run **terraform --version** to verify it is workable

#. Create AWS config

    - Create a new folder for test purposes
    - Copy and paste following code, it will help you to create a file named **aws.tf**

        .. code-block:: bash
        
            echo '
            # will create ssh key for each instance, keep key name different
            variable "key_name" {}
            variable "instance_num" {}

            # using your access_key and secret_key
            provider "aws" {
                region = "ap-northeast-2"
                access_key = "xxx"
                secret_key = "xxx"
            }

            # create ssh key pair
            resource "tls_private_key" "example" {
                algorithm = "RSA"
                rsa_bits  = 4096
            }

            # upload public key to aws, using defined name
            resource "aws_key_pair" "generated_key" {
                key_name   = "${var.key_name}"
                public_key = "${tls_private_key.example.public_key_openssh}"
            }

            # save private key to output for CLI
            output "privatekey" {
                value = "${tls_private_key.example.private_key_pem}"
            }            

            # find the image name with regex in your self image list, 
            #data "aws_ami" "image" {
            #    name_regex = "^centos.*"
            #    owners     = ["self"]
            #}

            # or you could get standard image from public
            data "aws_ami" "latest-ubuntu" {
                most_recent = true
                owners = ["099720109477"] # Canonical
                filter {
                    name   = "name"
                    values = ["ubuntu/images/hvm-ssd/ubuntu-xenial-16.04-amd64-server-*"]
                }
                filter {
                    name   = "virtualization-type"
                    values = ["hvm"]
                }
                filter {
                    name   = "root-device-type"
                    values = ["ebs"]
                }
            }

            # create instance
            resource "aws_instance" "example" {
                # using count to create multi instances, unfortunately, this character do not support in alicloud
                count         = "${var.instance_num}"
                ami           = data.aws_ami.latest-ubuntu.image_id
                instance_type = "t2.micro"
    
                # using the key name we just create
                key_name      = "${aws_key_pair.generated_key.key_name}"

                tags = {
                    name = "TerrVM"
                }

                # after instance created successfully, will try to create a connection to execute some commands
                connection {
                    host        = "${self.public_ip}"
                    type        = "ssh"
                    user        = "ubuntu" #default user in ami
                    private_key = "${tls_private_key.example.private_key_pem}"
                }

                # remote-exec will execute commands in your AWS EC2 instance
                provisioner "remote-exec" {
                    inline = [
                        "echo ${self.public_ip} > pub_ip_addr",
                    ]
                }

                # local-exec will execute commands in this Terraform VM to save the public ip address to a temproary file
                provisioner "local-exec" {
                    command = "echo ${self.public_ip} > /tmp/pub_ip_addr"
                }
            }

            # print something in stdout
            output "publicip" {
                value = "${aws_instance.example[*].public_ip}"
            }
            ' |tee aws.tf

#. run **terraform**

    - Execute the following commands to launch AWS EC2 instances

        .. code-block:: bash

            terraform init
            terraform apply -var key_name="tfkey-111" -var instance_num=3

    - Execute the following commands to get some variable we define in output

        .. code-block:: bash

            terraform output publicip
            terraform output privatekey

    - Execute the following commands to terminate AWS EC2 instances

        .. code-block:: bash

            terraform init
            terraform destroy -var key_name="tfkey-111" -var instance_num=3


Key Takeaways
+++++++++++++

Configuration Management vs Provisioning
----------------------------------------

- **Chef, Puppet, Ansible, and SaltStack** are all configuration management tools, which means they are designed to install and manage software on existing servers. 
- **CloudFormation and Terraform** are provisioning tools, which means they are designed to provision the servers themselves (as well as the rest of your infrastructure, like load balancers, databases, networking configuration, etc), leaving the job of configuring those servers to other tools.

Mutable Infrastructure vs Immutable Infrastructure
--------------------------------------------------

- Configuration management tools such as **Chef, Puppet, Ansible, and SaltStack** typically default to a mutable infrastructure paradigm. 
    
    - Best scenario is if you try to do some advanced or customized configuration in your deployment

- Provisioning tools such as **Terraform** typically default to a immutable infrastructure paradigm.

    - Best scenarios is if you just need basic OS and docker or kubernetes, no more customization
    - If you try to do some customization after provisioning with terraform, it will be not very elegant.

Procedural vs Declarative
-------------------------

- **Chef and Ansible** encourage a procedural style where you write code that specifies, step-by-step, how to to achieve some desired end state.
- **Terraform, CloudFormation, SaltStack, and Puppet** all encourage a more declarative style where you write code that specifies your desired end state, and the IAC tool itself is responsible for figuring out how to achieve that state.

Additional Reading
------------------

- `Compare Terraform with Chef/Ansible/Puppet/Saltstack/Cloud formation <https://blog.gruntwork.io/why-we-use-terraform-and-not-chef-puppet-ansible-saltstack-or-cloudformation-7989dad2865c>`_
- `Introduce Terraform <https://blog.gruntwork.io/an-introduction-to-terraform-f17df9c6d180>`_

How about Nutanix Calm
----------------------

- Calm should be positioned as automation tool for **Application Lifecycle Management**. From application perspective to management all VMs on any infrastructure. 
- Calm could eliminate technical fragmentations for your infrastructure. Help IT to leverage or integrate existed tool to a single pane of glass.
- Calm not only focus on deployment, but operation. Allow more operation tasks to be defined to make routing jobs more easier.
- Let end users to consume IT resources more easier with SSP and Marketplace.

- Offical Calm Pitch

    - Calm is a multi-cloud application management framework delivered by Nutanix.  Calm provides application automation and lifecycle management natively integrated into the Nutanix Platform.  With Calm, applications are defined via simple blueprints that can be easily created using industry standard skills and control all aspects of the application’s lifecycle, such as provisioning, scaling, and cleanup. Once created, a blueprint can be easily published to end users through the Nutanix Marketplace, instantly transforming a complex provisioning ticket into a simple one-click request. 
    - **One-Click Self-Service**: Self-service can now be delivered with Nutanix’s signature one-click simplicity
    - **Natively Nutanix Integration**: No need to install a new fleet of management tools and HCLs
    - **Multi-Cloud Adaptability**: Define applications once, Calm can provision them to public clouds when needed, providing a single self-service portal for all resources
    - **Flexible and Open Automation**: Augment and integrate with any tool or product already in use – Calm can call any API and be called by any API
    - **No new complex skills required**: Calm uses industry standard skills - such as bash, PowerShell and Python – to automate every aspect of an application so you can jump right in and get started 
