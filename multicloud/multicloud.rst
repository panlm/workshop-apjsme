.. title:: Multi Cloud Integration

.. _multicloud:

-----------------------
Multi Cloud Integration
-----------------------

GCP
+++

#. Login your gcp account under *project* in *nutanix* orgnization, for example **APAC Solution DEMO**, create *Service accounts* for your calm demo

    .. figure:: images/gcp1.png

    - Goto **IAM & admin**

    .. figure:: images/gcp1.png

    - Choose **Service accounts** from left panel
    - Choose **Create key** from action list of existed service account in right panel
    - Choose **JSON** format, and then click **CREATE**
    - **Save** the key locally for following demo

#. Update Calm settings

    - Click **Settings** of left navigate bar in Calm UI, Goto **Providers** tab.
    - CLick **Add Provider**

        - **Name** - GCP
        - **TYPE** - GCP
        - **Service Account File** - choose the file you just download from gcp
        - **Save** and **Verify**

        .. figure:: images/gcp2.png

#. Update Project settings

    - **Infrastructure** - choose *Local and Cloud resources* if needed
    - **GCP** - choose the GCP account name you just created
    - **Save**

Azure
+++++

#. Check this video out: https://www.youtube.com/watch?v=7wNCiw1Jn5A

#. Get directory ID

    - **Azure Active Directory** - **Properities** - **Directory ID**
    - copy directory ID to **Directory/Tenant ID** in azure provider settings

#. Get application ID & key

    - **Azure Active Directory** - **App registrations** - **New application registration**

        - name - *will be used below*
        - app type - Web app / API
        - sign-on URL - https://10.139.80.4:9440/console/#page/explore/calm
        - get **application ID** after click create

        - **settings** in this registered application

            - keys - add description of key and expires
            - save keys, you will get the key value

    - copy application ID to **Application/Client ID** in azure provider settings
    - copy key to **Client Key/Secret** in azure provider settings

#. Get subscription ID

    - **resource groups** - Add
    - open resource group and click **Access control** 
    - **Add** - **Add role assignment**

        - **Role** - **Contributor**
        - **Select** - *the application registration* you just created before
        - **Save**

    - copy subscription ID to **Subscription ID** in azure provider settings

#. now you could save and verify azure provider settings, and add it to your project.

#. Goto **Availability sets**, create new one for your existed resource group.
#. Goto **Network security groups**, create new one for your existed resource group.

    - open the network security group you just create and set **Inbound security rules**
    - open port you want to expose

#. Goto **Virtual Networks**, create on for your internal network

    - **Address space** - 10.255.255.0/24
    - **Address range** - 10.255.255.0/25

AWS EC2
+++++++

#. Goto **IAM** service on AWS
#. Click **Groups** from left navigate bar, Click **Create New Group** from top button

    - **Group Name** - calm_ec2
    - **Attach Policy** - *IAMReadOnlyAccess* and *AmazonEC2FullAccess*
    - review as following screenshot and **Create Group**

    .. figure:: images/aws5.png

#. Click **Users** from left navigate bar, Click **Create New User** from top button

    - **User Name** - calm_ec2
    - **Access Type** - check *Programmatic access*
    - **Set permissions** - *Add user to group*
    - **Group** - *calm_ec2* (we created just now)
    - **Add Tags** - *skip*
    - review as following screenshot and **Create User**

    .. figure:: images/aws13.png

    .. figure:: images/aws14.png

    - note down **Access key ID** and **Secret access key**

#. Prepare ssh key

    - Goto **EC2** service on AWS
    - Click **Key Pairs** from left navigate bar
    - Click **Import Key Pair** from top button, and select your public key or use this one --> :ref:`ssh_key_pub`

#. Prepare images

    - Goto **EC2** service on AWS
    - Click **instance** from left navigate bar
    - Launch instance as you needed
    - **create image** from this instance

#. Prepare security group

    - Goto **EC2** service on AWS
    - Click **Security Groups** from left navigate bar
    - Create a security group or modify existed one as follow

        - Inbound

            .. figure:: images/secgroup1.png

        - Outbound

            .. figure:: images/secgroup2.png

#. Update Calm settings

    - Click **Settings** of left navigate bar in Calm UI, Goto **Providers** tab.
    - CLick **Add Provider**

        - **Name** - *calm_aws*
        - **TYPE** - *AWS*
        - **Access key ID** - *get access key id from previous step*
        - **Secret access key** - *get secret access key from previous step*
        - **Save** and **Verify**

#. Update Project settings

    - **Infrastructure** - choose *Local and Cloud resources* if needed
    - **AWS** - choose the AWS account name you just created
    - **Save**

Kubernetes
++++++++++

Karbon
------


Google GKE
----------


Azure AKS
---------


Amazon EKS
----------




