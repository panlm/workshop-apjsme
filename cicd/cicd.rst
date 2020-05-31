.. title:: CI/CD Environment

.. _cicd:

------------------------
Create CI/CD Environment
------------------------

Import Blueprints
+++++++++++++++++

#. Please download 2 blueprints for this lab (if prompt password for blueprints, using `nutanix/4u`): 
    
    - :download:`CICD-Base.json <https://github.com/panlm/NTNX/raw/master/calm/blueprints/CICD-Base.json>`
    - :download:`CICD-App.json <https://github.com/panlm/NTNX/raw/master/calm/blueprints/CICD-App-noEpoch.json>`

#. upload blueprints

#. download and import ubuntu image for these blueprint :download:`ubuntu template <https://s3.ap-northeast-2.amazonaws.com/panlm-images/ubu-template.qcow2>`

Edit & Launch CI/CD Blueprint
+++++++++++++++++++++++++++++

#. Edit **CICD Base** blueprint:

    - In Application Profile

        - **initial_app_deploy_blueprint** - *input your CICD App blueprint name*
        - **initial_code_seed_location** - ``https://s3.ap-northeast-2.amazonaws.com/panlm-images``
        - **jenkins_public_key** - *Your public key*
        - **nutanix_public_key** - *Your public key*
        - **pc_instance_ip** - *Your Prism Central IP*

    - In Credentials

        - **Ubuntu Credential** - **nutanix/4u**
        - **Prism Central User** - *Your Prism Central usernamd and password*
        - **Nutanix Key** - *Your private key*
        - **Jenkins Key** - *Your private key*
        - **Docker Registry Credential** - **nutanix/4u**


    - In each service 

        - In **VM** Tab, **Image** - choose **ubu-template.qcow2**
        - In **VM** Tab, **Network adapters**, - choose **default**

    - **Save** blueprint

    - Launch this blueprint first, it will take about 20+ mins. Will setup whole developing environment, including jenkins master/slave, gitolite, artifactory, docker registry and developor workstation.

    - Get all environment information from the *last* task in **Audit** table of launched application. You will use these information in following lab.

        .. figure:: images/cicd1.png

        - get jenkins url and admin's password 
        
            - URL: for example: ``http://10.132.129.116:8080/``
            - Password: *d63a4aa28e174180bc040892296dace9*

        - get developor workstation ip address 
        
            - for example: *10.132.129.219*

        - get artifactory url 

            - for example: ``http://10.132.129.136:8081/artifactory/webapp``

Edit Application Blueprint
++++++++++++++++++++++++++

.. note::

    You DO NOT need to launch this blueprint, this blueprint will be called by jenkins pipeline

#. Edit **CICD App** blueprint:

    - In Application Profile
    
        - **artifactory_ip** - input *artifactory_ip*, after *CICD Base* blueprint launched
        - **pc_instance_ip** - *Your Prism Central IP*
        - **epoch_aoc_host** - **nutanix.epoch.nutanix.com**
        - **epoch_org_id** - **8cb44812-1cd3-45c4-847d-43f3271d126f**
        - **download_host** - leave if blank, if you could download from internet directly.
        - **download_port** - leave if blank, if you could download from internet directly.

    - In Credentials

        - **Ubuntu Credential** - **nutanix/4u**
        - **Prism Central User** - *Your Prism Central usernamd and password*

    - In each service 

        - In **VM** Tab, **Image** - choose **ubu-template.qcow2**
        - In **VM** Tab, **Network adapters**, - choose **default**

    - **Save** blueprint

Developor Workstation
+++++++++++++++++++++

Commit Code
-----------

#. Open jenkins master url, login as admin. You will see we already have devops pipeline ready.

    .. figure:: images/cicd2.png

#. Log in **dev workstation** with *nutanix / nutanix/4u*

    .. code-block:: bash
    
        cd devops/
        git add * 
        git commit -m 'initial version'
        git push origin master

#. Backup to jenkins web UI, we will see devops pipeline is running. it will get newest code from gitolite and try to do some testing, after that will trig calm to launch the blueprint to host the application.

    .. figure:: images/cicd3.png

#. From prism central UI, we will see the application blueprint was trigged

    .. figure:: images/cicd4.png

#. find **nginx** ip address and open it in browser.

    .. figure:: images/cicd5.png

    .. figure:: images/cicd6.png

Change Code
-----------

#. if we want to do some changes in our code, such as change *databox* color. Let's login to developer workstation agin

    .. code-block:: bash

        cd devops/
        vi web/src/css/style.css

    - search **databox** ( line 57 ), change **background-color** from *024394* to **FF4394**

        .. figure:: images/cicd7.png

#. after save the file, we need submit our change to git server

    .. code-block:: bash
    
        git add web/src/css/style.css
        git commit -m 'change background color'
        git push

#. login to jenkins, we will see the pipeline running again

#. after application deploy successful. You will have a **new** nginx ip address. Open if from browser, we will see new color in your application

        .. figure:: images/cicd8.png

Other components
++++++++++++++++

#. open artifactory web ui ``http://x.x.x.x:8081/artifactory/webapp``, login with default credential: **admin/password**

    .. figure:: images/arti1.png

    .. figure:: images/arti2.png

#. Access docker registry from browser 

    - ``https://x.x.x.x/v2/_catalog``

        .. figure:: images/dockr1.png

    - ``https://x.x.x.x/v2/devops/nginx/tags/list``

        .. figure:: images/dockr2.png



