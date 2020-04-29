.. title:: XPlay Demo

.. _xplay:

----------
XPlay Demo
----------

Memory self-healing capability
++++++++++++++++++++++++++++++

If VM has memory self-healing capability, when memory usage breach threshold, it could be added more memory automatically. No need any manual operations.

Overview
--------

In this Demo, we deploy 2 VMs application with predefined **alert policy** and **xplay playbook**. 

- The **alert policy** charge for generate alert when the VMs breach the threshold or anomalies detected.
- The **xplay playbook** will add memory to VMs when alerts generated. 

When you launch this application in production environment, it will create specific playbooks and alert policies for itself automatically, make it has memory self-healing capability. For your understand well, we break down here:

#. Upload blueprint and deploy application (2VMs)
#. Enable memory auto scaling up for this application 
#. Make some memory stress for the 2nd VM
#. Memory will be added to this VM, due to we got some Memory Alerts for this VM

Step 1
------

- Ensure you have Calm version `2.9.7.1`
- Download from here: :download:`xplay memory scaling up <https://github.com/panlm/NTNX/raw/master/calm/blueprints/memory-auto-scaleup-with-xplay.json>`
- Upload blueprint

    - **Passphrase** - *nutanix/4u*

    .. figure:: images/xplay1.png
        :width: 70 %

- Ensure you assign the image to **AppVM**
- Ensure you assign the network to **AppVM**
- Modify variable for your environment

    - **pc_ip** - *your_prism_central_ip_address*
    - **pc_username** - *your_prism_central_username*
    - **pc_password** - *your_prism_central_password*

    .. figure:: images/xplay2.png
        :width: 70 %

- Save
- Give the name to application after launch

    - **Name of the Application** - *MYAPP*

    .. figure:: images/xplay3.png

- After launch successfully, you will find 1 category named `MYAPP` and 2 VMs in it.

    .. figure:: images/xplay5.png

    .. figure:: images/xplay6.png

- Default memory for these VMs is 2GB

Step 2
------

- Enable predefine playbook for this application, put threshold `80` to it. When the memory usage over 80%, will trigger playbook to add more memory to VMs.

    .. figure:: images/xplay20.png

- Goto **Activity** --> **Alerts**, Open **Configure** --> **Alert Policy**. The alert policy will be created with threshold 80 automatically.

    .. figure:: images/xplay21.png

    .. figure:: images/xplay22.png
        :width: 90 %

- Goto **Operations** --> **Playbooks**. The playbook will be created for the alert policy automatically.

    .. figure:: images/xplay23.png

    .. figure:: images/xplay24.png

- In this playbook, it will add 1GB memory to VM when got alert from `MYAPP`

    .. figure:: images/xplay25.png

- Everything is configured well automatically, let's do some memory stress and see what will happen.

Step 3
------

- Goto **Services** --> **Calm** --> **Applications** --> `MYAPP` --> **Manage**
- Click **MemoryStress** action. (We define to run memory stress on the 2nd VM)

    .. figure:: images/xplay31.png

- Goto **Activity** --> **Alerts**, to check alerts (it will need several minutes)

    .. figure:: images/xplay32.png

- If we find the alert was generated, you could check detail info of this alert.

    .. figure:: images/xplay33.png

- As we expectation, when the alert was generated, the playbook should be run to solve this alert. Goto **Operations** --> **Playbooks**, to check **Plays** in playbook

    .. figure:: images/xplay34.png

- We could check the status of each step in this playbook

    .. figure:: images/xplay35.png

    - Here we could find **VM Add Memory** operation successed
    - But **Email** operation failed.
    - You could click **Detail** to see more infomation

Step 4
------

- Goto **VM List**, to check our VM has been scaled up

    .. figure:: images/xplay40.png


Clean your environment
----------------------

- Goto **Services** --> **Calm** --> **Applications** --> `MYAPP` --> **Manage**
- Find **MemoryStress** action and **Abort** it, click *black square* at the right side

    .. figure:: images/xplay50.png

- BTW, just click **Disable XPlay** to clean existed playbook and alert policy

Deep Dive
+++++++++

