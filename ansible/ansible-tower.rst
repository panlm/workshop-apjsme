.. title:: Ansible Tower Integration

.. _ansible-tower:

-------------------------
Ansible Tower Integration
-------------------------

Ansible Tower Integration
+++++++++++++++++++++++++

1. Install Ansible Tower
------------------------

#. add image using this url: `centos6.qcow2 <https://s3.ap-northeast-2.amazonaws.com/panlm-images/centos6.qcow2>`_
#. Create VM from this image, login with default credential: 

    - username: ``root``
    - password: ``nutanix/4u``

#. Generate ssh key pair

    .. code-block:: bash

        ssh-keygen -t rsa
        cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

#. Download ansible bundle

    .. code-block:: bash

        wget 'https://releases.ansible.com/ansible-tower/setup-bundle/ansible-tower-setup-bundle-2.4.5-1.el6.tar.gz'
        tar xf ansible-tower-setup-bundle-2.4.5-1.el6.tar.gz

#. start to configure ansible tower

    .. code-block:: bash

        cd ansible-tower-setup-bundle-2.4.5-1.el6
        ./configure

    - when configuration start, you need to interactive with it, see ``<-----------``

    .. code-block:: language
    
        -------------------------------------------
        Welcome to the Ansible Tower Install Wizard
        -------------------------------------------

        This wizard will guide you through the setup process.

        PRIMARY TOWER MACHINE
        Tower can be installed (or upgraded) on this machine, or onto a remote machine
        that is reachable by SSH.

        Note: If using the High Availability features of Tower, you must use DNS
        resolvable hostnames or IP addresses (do not use "localhost").

        Enter the hostname or IP to configure Ansible Tower
        (default: localhost): 10.55.52.112                                             <-----------

        DATABASE
        Tower can use an internal database installed on the Tower machine, or an
        external PostgreSQL database. An external database could be a hosted database,
        such as Amazon's RDS.

        An internal database is fine for most situations. However, to use the High
        Availability features of Tower, an external database is required.

        If using an external database, the database (but not the necessary tables) must
        already exist.

        Will this installation use an (i)nternal or (e)xternal database? i             <-----------

        PASSWORDS
        For security reasons, since this is a new install, you must specify the
        following application passwords.

        Enter the desired Ansible Tower admin user password:                     admin <-----------
        Enter the desired Munin password:                                        admin <-----------

        CONNECTION INFORMATION
        Enter the SSH user to connect with (default: root):                            <-----------

        Will you be using SSH keys (Y/n)? y                                            <-----------

        Please specify the path to the SSH private key: /root/.ssh/id_rsa              <-----------

        REVIEW
        You selected the following options:

        The primary Tower machine is: 10.55.52.112
        Tower will operate on an INTERNAL database.
        Using SSH user: root

        Are these settings correct (y/n)? y                                            <-----------
        Settings saved to /root/ansible-tower-setup-
        bundle-2.4.5-1.el6/tower_setup_conf.yml.

        FINISHED!
        You have completed the setup wizard. You may execute the installation of
        Ansible Tower by issuing the following command:

        # Add your SSH key to SSH agent.
        # You may be asked to enter your SSH unlock key password to do this.
        ssh-agent bash
        ssh-add /root/.ssh/id_rsa
        ./setup.sh

    - As prompt, run these commands

    .. code-block:: bash

        ssh-agent bash
        ssh-add /root/.ssh/id_rsa
        ./setup.sh
        
    - wait until setup finished

2. Setup Ansible Tower
----------------------

#. Access the Ansible Tower's IP address to open Web UI

    .. figure:: images/tower-ui1.png

    - input Ansible Tower Trial License

        .. code-block:: json

            {
                "company_name": "gmail", 
                "contact_email": "stevenpan@gmail.com", 
                "contact_name": "leiming pan", 
                "hostname": "e5e213cd2495405d89d5ec4219d60487", 
                "instance_count": 10, 
                "license_date": 2123563929, 
                "license_key": "d69b7cf6d4986e7ba21252ef5bc797e1848866d83056199caed2ec91752261c4", 
                "license_type": "basic", 
                "subscription_name": "Red Hat Ansible Tower, Self-Support (10 Managed Nodes)"
            }

    .. figure:: images/tower-ui2.png

#. Go to **setup** page from top-right button 

    .. figure:: images/tower-setup.png

#. Click **Inventory Scripts**, and then click ``plus`` button from top-right corner to add a new script

    .. figure:: images/tower-inv-script2.png

    - **Name** - *prism central script*
    - **Organization** - *Default*
    - **Custom Script** - copy and paste from this page: `prism_central.py <https://raw.githubusercontent.com/panlm/ansible-nutanix-prismcentral-inventory/filter_vm_AT/prism_central.py>`_
    - **Save**

#. Back to setup page and click **Credentials**, and then click ``plus`` button from top-right corner to add a new credential

    .. figure:: images/tower-cred2.png

    .. figure:: images/tower-cred3.png

    - **Name** - *Nutanix VM*
    - **User that owns this credential** - *admin*
    - **Type** - *Machine*
    - **Username** - *root*
    - **Password** - *nutanix/4u*
    - **Save**

#. Click **Projects** on top of the page, and then click ``plus`` button to add a new project

    .. figure:: images/tower-proj1.png

    .. figure:: images/tower-proj2.png

    - **Name** - *proj1*
    - **Organization** - *Default*
    - **SCM Type** - *Git*
    - **SCM URL** - *https://github.com/ansible/ansible-tower-samples*
    - **SCM Branch** - *keep it null*
    - **SCM Credential** - *keep it null*
    - **SCM Update Options** - **Update on Launch** - *checked*
    - **Save**
    - wait until project update successfully

#. Click **Inventories** on top of the page, and then click ``plus`` button to add a new inventory

    .. figure:: images/tower-inv1.png

    - **Name** - *Nutanix Inventory*
    - **Organization** - *Default*
    - **Save**

#. Go to **Nutanix Inventory** to add group

    .. figure:: images/tower-inv2.png

    - Click ``plus`` button from left side to add a new group

    - In **Properities** tab

        .. figure:: images/tower-grp1.png

        - **Name** - *grp1*

    - In **Source** tab

        .. figure:: images/tower-grp2.png

        - **Source** - *Custom Script*
        - **Custom Inventory Script** - *prism central script* (we just added)
        - **Environment Variables** - *following is a sample, please modify them as your environment*

            .. code-block:: yaml
            
                ---
                PC_IP_ADDR: 10.42.98.39
                PC_USERNAME: admin
                PC_PASSWORD: nx2Tech264!

        - **Update Options** - **Update on Launch** - *checked*
        - **Save**

    .. figure:: images/tower-grp3.png

    - Click ``Start sync process`` button to run inventory script to get hosts

    .. note:: this script just get VM with "AT-" prefix, due to we could not manage over 10 VMs with Ansible Tower Trial License
    
#. Click **Job Templates** on top of the page, and then click ``plus`` button to add a new job template

    .. figure:: images/tower-job1.png

    .. figure:: images/tower-job2.png

    - **Name** - *job1*
    - **Job Type** - *Run*
    - **Inventory** - *Nutanix Inventory*
    - **Project** - *proj1*
    - **Playbook** - *hello_world.yml*
    - **Allow Provisioning Callbacks** - *checked*
    - Click right button to generate **Host Config Key**
    - **Machine Credential** - *Nutanix VM*
    - **Save** and you will be prompt these important info

        .. figure:: images/tower-job3.png

#. Click **Jobs** on top of the page, wait for magic happen ;)

    .. figure:: images/tower-job4.png

3. Create VM managed by Tower
-----------------------------

#. Download blueprint from HERE: :download:`blueprint: ansible-awx-managed-vm <./ansible-tower-managed-vm.json>`

#. This is a simple blueprint with one service. One bash task in service's **Package** --> **Install** task

    .. note:: here is an sample, use your ``HOST CONFIG KEY`` and ``PROVISIONING CALLBACK URL``
    
    .. code-block:: bash

        set -x
        curl -k --data "host_config_key=d79edf528d0b25209aa65a0dd2bdb0c7" https://52.79.250.3:4443/api/v1/job_templates/7/callback/

#. Modify this blueprint

    - Variables

        - **host_config_key** - *your host config key*
        - **callback_url** - *your callback url*

    - Assign a linux image, **centos6.qcow2**
    - **unchecked** cloudinit script
    - Add nic and assign network
    - Edit credential 

        - **Credential Name** - *root*
        - **Username** - *root*
        - **Secret Type** - *Password*
        - **Password** - *nutanix/4u*

#. Save and launch blueprint

4. Check playbook is running on VM
----------------------------------

#. After the blueprint launched successfully, back to Ansible Tower UI, check jobs running on this VM automatically

    .. figure:: images/tower-job5.png

#. Click ``green`` point, you could get more detail information of this job

    .. figure:: images/tower-job6.png

#. Click **Inventories** on top of the page, and then click **Nutanix Inventory**, you will find VM added to hosts list on right side

    .. figure:: images/tower-host.png

Reference
+++++++++

- Ansible 2.4 `Document <https://docs.ansible.com/ansible-tower/2.4.0/html/>`_





