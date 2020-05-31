.. title:: Labs for APJ SE

.. toctree::
  :maxdepth: 2
  :caption: Released Labs
  :name: _labs
  :hidden:

  portal/portal
  integration-noEpoch/integration-noEpoch
  ansible/ansible-awx
  ansible/ansible-tower
  cicd/cicd
  terraform/terraform
  xplay/xplay
  elk/elk

.. toctree::
  :maxdepth: 2
  :caption: Working Labs
  :name: _workinglabs
  :hidden:

  multicloud/multicloud
  infoblox/infoblox
  zabbix/zabbix

.. toctree::
  :maxdepth: 2
  :caption: Appendix
  :name: _appendix
  :hidden:

  appendix/glossary
  appendix/otherstuff

.. _getting_started:

-------------
Getting Start
-------------

Welcome to labs for APJ SE


Labs we have
++++++++++++

Released Labs
-------------

- :ref:`portal` (Jul 2019)
- :ref:`integration-noEpoch` (Oct 2019)
- :ref:`ansible-awx` (Apr 2019)
- :ref:`ansible-tower` (Apr 2019)
- :ref:`cicd` (Mar 2019)
- :ref:`terraform` (Oct 2019)
- :ref:`xplay` (Mar 2020)
- :ref:`elk` (May 2020)

Working Labs
------------

- :ref:`multicloud` (May 2019)
- :ref:`infoblox`
- :ref:`zabbix` (Jul 2019)

Obseleted Labs
--------------

- :ref:`integration` (Mar 2019)

.. _ssh_key:

Sample SSH Keys
+++++++++++++++

.. _ssh_key_priv:

Private Key
-----------

::

    #copy and paste to CLI
    echo 'LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUFBQkc1dmJtVUFBQUFFYm05dVpRQUFBQUFBQUFBQkFBQUJGd0FBQUFkemMyZ3RjbgpOaEFBQUFBd0VBQVFBQUFRRUFzdmZ0ZlcxWFl6ZGxIcmY0d21RKzB2dEJrQVpiOUhqcnRyWENxc2VhZjhGb1g0ay9EUTlGCk4zcEpSdFZKVTAyMFFQdGJLZ1I1TWFBOUJuUzdFbGRDTEsvdDBkeFpTWUorN29YZENNeURZMmpmVHoreU5nK0ZBRXdMMUsKWHRkNzZvYkVzVHhCR29jUFQzcTdzandBYUtXWjJaSVhLaHhQc2Z4UjNnUkg5bldxcG1mMkplWjVYbzFIZVhwZVBTcEV2cwpDZ28zOEU1cXlBMkJtMkFMYXYvYmdLWFRjYk1zdlJBb0ZjcnJudVpTTTRsNTFlMGVQMlQzVGdmcVdZdTArRW5Pd2NyUjF1ClF2NEtOTFQ2QU9vejVEdGZXY2cxZmNzK29sT01kaDZPeFVUajkyOFZkN0dScGt6Tm95YXpuQUhkMGFMSnRyQ1JHbU1VajkKa3dhekNoQlNTd0FBQStEQ0kwbWx3aU5KcFFBQUFBZHpjMmd0Y25OaEFBQUJBUUN5OSsxOWJWZGpOMlVldC9qQ1pEN1MrMApHUUJsdjBlT3UydGNLcXg1cC93V2hmaVQ4TkQwVTNla2xHMVVsVFRiUkErMXNxQkhreG9EMEdkTHNTVjBJc3IrM1IzRmxKCmduN3VoZDBJeklOamFOOVBQN0kyRDRVQVRBdlVwZTEzdnFoc1N4UEVFYWh3OVBlcnV5UEFCb3BablpraGNxSEUreC9GSGUKQkVmMmRhcW1aL1lsNW5sZWpVZDVlbDQ5S2tTK3dLQ2pmd1RtcklEWUdiWUF0cS85dUFwZE54c3l5OUVDZ1Z5dXVlNWxJegppWG5WN1I0L1pQZE9CK3BaaTdUNFNjN0J5dEhXNUMvZ28wdFBvQTZqUGtPMTlaeURWOXl6NmlVNHgySG83RlJPUDNieFYzCnNaR21UTTJqSnJPY0FkM1Jvc20yc0pFYVl4U1AyVEJyTUtFRkpMQUFBQUF3RUFBUUFBQVFBb3JDdXU2NkNHamRwUFJ1UWoKMllCbGxuQnArT2dCQVZJZ2JlSlZ5Wk1WSWJGRXRQNDlTNUVoY0lzaXErcEVJazZxemZVRDhZeFJlT2NsaG5YVlR6dGN5SQphMXdPd1J4clJ1Sk1IODgrMlFOQTg4QlcvTTFXNFdpVEhQRy82QnpqU2NsOXRnSGRzNEFKUWcxU0RrelJlNEVoYnhBUW8rCnFBdXFVb1hiUzFFRHk0Qzk2UUpJemhJN1VpSmkxMzlyTHhLSlNsYXpsMHZVVnU5ZUd4d3ZWR1NoL2RQNWUyQXFhd2w3aE4KMmV2Y3lRWTdhUjhRN1BPbjdiWnhOM3JFZUE4WlhNWmpRSDFQcFJpd3JpeEQ4M3NrQmhYWUlLRkwyVEptd2FMT0tobjNCbQpEcnFNQ0RJVzNKVUU1VDA2Qi9oc0o2ZWZDc0tDa0trTnNTejZCVTJzdE9teEFBQUFnUUNPaWxMOHQzUUY5MHcxNkh5QUlMClhacms5SlhFKzROdGxTNHRsemdHWk5qT1RCVHVoTWdscU54b2l2QmFScHZhS25WdHRBQy9ZRUJMcUpmR21XaGlET09KSzUKanB4WFpQWUxyVW82ZjVKZFVGSGRUU1YzWUQyUWFlWEV5eFhpY005bjJnWDV0dVN2KzdOblFubHRSbzNuVjZJRGdBTW5pagpkcmFaOXdWWm9oeEFBQUFJRUEyYS9SVm1XSC9lbExkVUtPcUNtNEttRmJEdWQ0VmIvUkpVQkZVU0hVZlc2Nm1lS0pRNFo5CmpONHg3ZGVYZ0NvWlgwZUV3NlRyTkg2c0VjcE52Zk9RMWdlaW53cS95YjBJSStoU3R3TW1wSndYUFBXeHFTeDkxWFB5dXgKWkhqdHkzVHlyL2pXaWRqRVVodWhZVExnaVlVYlhybHFoSTU2TkFxdGNxRXRZenJ5Y0FBQUNCQU5KM21ocHYySlVPcEhUTwpOZUVLRnZEcmgrL25BcE16QldYdDBHYTFwcVF3NGttZjgxUGFGSEo0eE43SEpWL25pY1FzdDNtajZCdDMxb1VVdzRma3N4ClNiU1lCckhYUFAxNVI3a0l4VFBHL290bWRsN21XNFgvdStOcVQ5L2FyN2Y3QThScEQrS3A2dkU3UFp1Q1Z6c3UydVhxekoKeUpRN1NQQmxyUHhMNFhvOUFBQUFKbk4wWlhabGJuQmhia0J6ZEdWMlpXNXdZVzV6TFUxaFkwSnZiMnN0VUhKdkxteHZZMgpGc0FRSURCQT09Ci0tLS0tRU5EIE9QRU5TU0ggUFJJVkFURSBLRVktLS0tLQo=' |base64 -D

.. _ssh_key_pub:

Public Key
----------

::

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy9+19bVdjN2Uet/jCZD7S+0GQBlv0eOu2tcKqx5p/wWhfiT8ND0U3eklG1UlTTbRA+1sqBHkxoD0GdLsSV0Isr+3R3FlJgn7uhd0IzINjaN9PP7I2D4UATAvUpe13vqhsSxPEEahw9PeruyPABopZnZkhcqHE+x/FHeBEf2daqmZ/Yl5nlejUd5el49KkS+wKCjfwTmrIDYGbYAtq/9uApdNxsyy9ECgVyuue5lIziXnV7R4/ZPdOB+pZi7T4Sc7BytHW5C/go0tPoA6jPkO19ZyDV9yz6iU4x2Ho7FROP3bxV3sZGmTM2jJrOcAd3Rosm2sJEaYxSP2TBrMKEFJL stevenpan@stevenpans-MacBook-Pro.local

.. _cloudinit:

standard Cloud-Init Script with *Username and Password*
-------------------------------------------------------

-  for centos image, default username is *centos*, you could setup password for this user with following cloud init script

    .. code-block::

        #cloud-config
        disable_root: False
        ssh_pwauth: True
        password: nutanix/4u
        chpasswd: { expire: False }


standard Cloud-Init Script with *SSH KEY*
-----------------------------------------

-  for centos image, default username is *centos*, you could use ssh key for this user with following cloud init script. **@@{public_key}@@** is a variable in Calm, you should define it in your blueprint.

    .. code-block::

        #cloud-config
        disable_root: False
        ssh_enabled: True
        ssh_pwauth: True
        users:
          - name: centos
            ssh-authorized-keys:
              - ssh-rsa @@{public_key}@@
            sudo: ['ALL=(ALL) NOPASSWD:ALL']










