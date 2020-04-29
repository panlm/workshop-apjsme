.. title:: Ansible AWX Integration

.. _ansible-awx:

-----------------------
Ansible AWX Integration
-----------------------

AWX Integration
+++++++++++++++

Overview
--------

- Online video is here: `Video <https://youtu.be/rWOAB9SLT5U>`_
- Update:

    - 2020/03/16

        - add more specific requirement ( log display, limit/variable parameter )
        - fix docker-compose python library install failed ( ==1.24 )

- Todo:

    - will change manual operation to api, make everyone could demo

Create AWX
----------

#. Using default CentOS image, copy this url and **Add Image** from **URL**. `CentOS-7-x86_64-GenericCloud-1801-01.qcow2 <http://download.nutanix.com/calm/CentOS-7-x86_64-GenericCloud-1801-01.qcow2>`_

#. Download blueprint from HERE: :download:`blueprint: ansible-awx <./ansible-awx.json>`

#. Modify blueprint as you needed

    - **Credentials** - *use your private key* or refer --> :ref:`ssh_key_priv`
    - **Variables** in **Application Profile**
    
        - **public_key** - *use your public key* or refer --> :ref:`ssh_key_pub`

    - **image** - *select the image you just created*
    - **cloudinit** - *use your cloudinit script* or refer --> :ref:`cloudinit`
    - **network** - *select network*
    - **Save** the blueprint

#. After blueprint launched, you will get a workable AWX. Open browser to access the AWX VM's IP address. Default credential is **admin/password**

    .. figure:: images/awx1.png

Quick Settings
--------------

- Run this script to instead of all steps in **Basic Settings**

    - Download from HERE: :download:`script: ansible-awx-autosetup.py <./ansible-awx-autosetup.py>`
    - Setup environment before you run. Here is an example:

        .. code-block:: bash
        
            export PC_IP=10.55.7.40
            export PC_TOKEN=$(echo -e 'admin:password\c' |base64)
            export ANSIBLE_IP=10.55.7.90

- Go to *Create VM managed by AWX* chapter directly.

Basic Settings
--------------

#. Go to **Inventory Scripts** from the left side, click ``green`` plus button on the right side to add new one

    .. figure:: images/awx-inv-script.png

    - **Name** - *prism central*
    - get script from here `prism_central.py <https://raw.githubusercontent.com/panlm/ansible-nutanix-prismcentral-inventory/master/prism_central.py>`_
    - **Save**

#. Go to **Inventories** from the left side, click ``green`` plus button on the right side to add new one

    .. figure:: images/awx-inv1.png

    - **Name** - *Nutanix Inventory*
    - **Save**

#. Go to **SOURCES** from the top

    .. figure:: images/awx-inv2.png

#. Click ``green`` plus button to add a **Source** to this inventory

    .. figure:: images/awx-inv3.png

    - **NAME** - *prism central*
    - **SOURCE** - *Custom Script*
    - **CUSTOM INVENTORY SCRIPT** - *select the inventory script you just added*
    - **UPDATE ON LAUNCH** - *checked*
    - **ENVIRONMENT VARIABLES** - *prism_central_ip*, *prism_username*, *prism_password*

        .. code-block:: yaml
        
            ---
            PC_IP_ADDR: 10.42.98.39
            PC_USERNAME: admin
            PC_PASSWORD: <your_password>
    
    - **Save**

#. Start sync

    - Go back to **SOURCE** from top navigator path

        .. figure:: images/awx-navigator1.png

    - Click ``Start sync process`` to capture VMs info to inventory

        .. figure:: images/awx-inv4.png

    - The ``cloud`` icon (left of source name) will tune to green, click it for more detail logs

        .. figure:: images/awx-inv5.png

    - After sync finished, check **HOST** tab. all VMs in your cluster will be captured and displayed

        .. figure:: images/awx-inv6.png

#. Go to **Credentials** from left side and add new one for VMs which we will create later

    .. figure:: images/awx-cred2.png

    - **NAME** - *Nutanix VM*
    - **ORGANIZATION** - *Default*
    - **CREDENTIAL TYPE** - *Machine*
    - **USERNAME** - *centos*
    - **SSH PRIVATE KEY** - *user your private key* or refer --> :ref:`ssh_key_priv`
    - **PRIVILEGE ESCALATION METHOD** - *sudo*
    - **PRIVILEGE ESCALATION USERNAME** - *root*
    - **Save**

    .. note:: USERNAME and Password/Private Key should be same with the credential in ``ansible-awx-managed-vm`` blueprint

#. Go to Projects

    - click ``Get latest SCM revision``, it will download ansible playbooks to local for this lab

        .. figure:: images/awx-proj0.png

    - Open this **Demo Project**, you will find **SCM URL**. this is the github which ansible playbooks download from

        .. figure:: images/awx-proj2.png

        - Prefer URL - `https://github.com/panlm/myansible.git`
        - Default URL - `https://github.com/ansible/ansible-tower-samples`
        - If you change the URL, please remember to refresh the project

    - Click **JOB TEMPLATES**

        .. figure:: images/awx-proj3.png

    - Open **Demo Job Template**, we will re-use it in our lab

        .. figure:: images/awx-proj4.png

        - **INVENTORY** - *Nutanix Inventory* (we just create it)
        - **CREDENTIAL** - *Nutanix VM* (we just create it)
        - **PLAYBOOK** - *hello_world.yml*

            .. note:: if you could not see playbook here, maybe need to fresh your project, see first step in this paragraph, ``Get latest SCM revision``
            
        - **ALLOW PROVISIONING CALLBACKS** - *checked*
        - write down the **PROVISIONING CALLBACK URL**, will be used in Calm blueprint
        - click right button to generate **HOST CONFIG KEY**, and write down it, will be used in Calm blueprint
        
            - get help for this **HOST CONFIG KEY**

                .. figure:: images/awx-proj5.png

        - **Save** and you will be prompt these important info

            .. figure:: images/awx-proj6.png

#. Go to **Jobs** from left side, and wait magic happen ...

Create VM managed by AWX
------------------------

#. Download blueprint from HERE: :download:`blueprint: ansible-awx-managed-vm <./ansible-awx-managed-vm.json>`

#. This is a simple blueprint with one service. One bash task in service's **Package** --> **Install** task

    .. note:: here is an sample, use your ``HOST CONFIG KEY`` and ``PROVISIONING CALLBACK URL``
    
    .. code-block:: bash

        set -x
        curl --data "host_config_key=629ff460-d58e-410c-a2d0-5e1557eded27" http://10.42.98.107:80/api/v2/job_templates/5/callback/

#. Modify this blueprint

    - Variables

        - **host_config_key** - *your host config key*
        - **callback_url** - *your callback url*
        - **public_key** - *inject your public key* or refer --> :ref:`ssh_key_pub`

    - Assign a linux image
    - Assign cloudinit script, use your cloudinit script or refer --> :ref:`cloudinit`
    - Add nic and assign network
    - Create a credential 

        - **Credential Name** - *centos*
        - **Username** - *centos*
        - **Secret Type** - *SSH Private Key*
        - **SSH Private Key** - *paste your private key* or refer --> :ref:`ssh_key_priv`

#. Save and launch blueprint

Check job is running on VM
-------------------------------

#. Back to AWX UI, go to **Jobs**

#. after the VM created by Calm, the job will running automatically to config this VM as your expectation

    .. figure:: images/awx-job1.png

#. click job for more detail information, including the VM ip address

    .. figure:: images/awx-job2.png

Advanced Settings
-----------------


Reference
+++++++++

- Jose Gomez's `Github <https://github.com/pipoe2h/ansible-nutanix-prismcentral-inventory>`_ and  `Video <https://youtu.be/rWOAB9SLT5U>`_
- Ansible AWX Project `Github <https://github.com/ansible/awx>`_
