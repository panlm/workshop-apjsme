.. title:: APJ SME Portal

.. _portal:

--------------
APJ SME Portal
--------------

Launch
++++++

#. Before you start

    - one CentOS 7 VM
    - Prism Central
    - (Option) Era VM

#. Setup docker environment

    .. code-block:: bash

        sudo yum install -y yum-utils device-mapper-persistent-data lvm2
        sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        sudo yum install -y docker-ce docker-ce-cli containerd.io
        sudo systemctl enable docker
        sudo systemctl start docker
        sudo -E usermod -a -G docker ${USER}

#. logout and relogin current user

#. download and run docker image

    .. code-block:: bash

        sudo docker pull panlm/ntnx:app2
        sudo docker run -d --name app2 -p 5000:5000 panlm/ntnx:app2

#. Open browser with your centos 7 ip address and port **5000** to access this app2. 

    - **http://x.x.x.x:5000/**

    .. figure:: images/p-login.png

#. login your mail address with **any characters** in password field.

    .. figure:: images/p-existed.png

#. Click **Load** to load existed settings or you could click **Input** to input your Prism Central / Era credentials


Sample Screenshots
++++++++++++++++++

Dashboard
---------

.. figure:: images/p-dashboard.png


VM with approval flow
---------------------

#. VM Management UI

    .. figure:: images/p-vm.png

#. Submit creating VM request

    - click **New**
    - select **Image**
    - select **Network**
    - choose **VM Computing Size**
    - choose **VM Storage Size**
    - click **Submit** for approval

    .. figure:: images/p-newvm.png

    - click **Approval Flow** - **Pending**, you will see you request is pending

    .. figure:: images/p-approval-1.png

#. Approve request using admin@nutanix.com

    - logout from right top icon
    - login **admin@nutanix.com** account, using any characters as your password
    - **Load** settings
    - goto **Dashboard**
    - goto **VM Pending** page
    - click **approve**

#. Login your account again, and you could deploy VM

    .. figure:: images/p-approval-2.png


Blueprint and Application
-------------------------

#. You could click blueprint name to see **App Profiles** in blueprint, also you could click **Launch** to launch this blueprint.

    .. figure:: images/p-blueprint.png

#. You could click application name to see **Actions** in application, also you could click **Delete** to delete this application.

    .. figure:: images/p-application.png

Era
---

#. You could list all databases managed by Era

    .. figure:: images/p-era.png

#. Click **New** to create database in Era. Please select all parameters relevanted to **PostgreSQL**

    .. figure:: images/p-newera.png

Billing
-------

.. figure:: images/p-billing.png

Monitoring
----------

.. figure:: images/p-monitor.png


