.. title:: Using ELK to insight your logs

.. _elk:

---------------------
Logs Insight with ELK
---------------------

Recently, I received some calls relevented to logs insight scenarios. If you try to get and analysis logs ASAP, even you try to create some alerts and actions based on your log real time analysis mechanism, there are some open source tools you could leverage. In this article, I will show you:

- In part 1, I will create ELK VM and forward Prism Central (PC) Logs to it, I will explain how to find **Nutanix Flow** logs in ELK.

- In part 2, it's a real request from field. I build a blueprint to create http service fleet, and add these VMs to F5 load balance, and forward http logs and metric to ELK ( we build ELK from part 1 ). Also I will configure F5 to log some customized http session performance data with **iRule** and forward to ELK as well.


Take away
+++++++++

- Calm could help you at infrastructure level, eliminate the friction of multi clouds and differnet technical stacks. You will have time to deep dive your applications to figure out what kind of indicates are valuable for your business.

- Choose right tools for APM statistics or endpoint to endpoint network performance. If Alert generated, it could trigger a notification, webhook or Calm RestAPI to do operation tasks automatically.

- Calm could integration with lots of 3-party products and solutions, in this case we hug **F5**

- ELK - Elasticsearch, Logstash, and Kibana (In EFK, F means Fluentbit)


Part 1: Collect Nutanix Flow Log through PC
+++++++++++++++++++++++++++++++++++++++++++

If you are demoing Nutanix Flow to potential customers or partners, you will be asked how to collect Nutanix Flow logs for audit? You could use this artical to setup ELK first, and show more granularity to them.

.. note::

    This is an advanced course, you will see more useful screenshots instead of step-by-step.

ELK environment
---------------

#. Please download blueprint for this lab (if prompt password for blueprints, using `nutanix/4u`): 
    
    - :download:`EFK.json <https://github.com/panlm/NTNX/raw/master/calm/blueprints/EFK.json>`

#. Launch it

    - you need to choose image for this VM, and network NIC
    - using cloud-init to customize it. (refer :ref:`cloudinit`)
    - ensure the credential you have matches the customization in cloudinit

#. After launch successfully, access Kibana with the VM's IP address with port *5601*

    - `http://x.x.x.x:5601`

Forward Prism Central logs to ELK
---------------------------------

#. Goto Prism Central Settings --> Syslog Server

    - Setting logging server to ELK VM with UDP port `10514`

        .. figure:: images/logserver1.png

    - Ensure Flow in data sources settings

        .. figure:: images/logserver2.png

#. Create a security policy

    - Enable **Policy Hit Log**

        .. figure:: images/flow1.png

    - this is my sample security policy for specific category named **hadoop**. I should categorize ELK VM to **hadoop**. 

        .. figure:: images/flow2.png

    - Any network traffic from/to ELK VM, will generate **policy hit log** and PC will forward them to ELK VM.

#. Access Kibana UI: `http://x.x.x.x:5601`

    - Goto **Management** --> **Index Patterns** --> **Create index pattern** 
    
        .. figure:: images/kibana7-1.png
    
    - Input "log*" as shown --> **Next Step**

        .. figure:: images/kibana7-2.png

    - Choose "@timestamp" as **Time Filter field name**, and then click **Create index pattern**

        .. figure:: images/kibana7-3.png

    - Goto **Discover** page, ensure the **INDEX PATTERN** is the one we just created. In this screenshot, we choose `log*`

        .. figure:: images/kibana7-4.png

    - Let's explain more about the first log in previous screenshot

        - first log **message** part: **<134>2020-05-31T12:42:15.058679+00:00 RTP-POC007-1 flow-hitCount4: INFO:2020/05/31 12:42:06 [7847abb0-285b-4ff9-bb40-271df1a0c229] test [Destroy] SRC=10.55.7.26 DST=10.55.7.140 PROTO=UDP SPORT=45214 DPORT=10514**

            - **<134>** - unknown
            - **2020-05-31T12:42:15.058679+00:00** - timestamp
            - **RTP-POC007-1** - AHV Hostname
            - **flow-hitCount4** - it's a flow hit log
            - **INFO:2020/05/31 12:42:06** - timestamp
            - **[7847abb0-285b-4ff9-bb40-271df1a0c229]** - security policy uuid
            - **test** - security policy name
            - **[Destroy]** - flow connection status
            - **SRC=10.55.7.26** - source ip addr
            - **DST=10.55.7.140** - destnation ip addr
            - **PROTO=UDP** - protocol
            - **SPORT=45214** - source port number
            - **DPORT=10514** - destnation port number

#. OK, It's time for you to play with Kibana. It's simple, right? let's go to part 2 for more complex.


Part 2: Customized session log statistics from F5
+++++++++++++++++++++++++++++++++++++++++++++++++

Background
----------

Based on transaction's RTT and concurrent to scale in/out VM fleet automatically.

    .. figure:: images/ppt1.png

HTTP Service Fleet
------------------

- You need another blueprint, it will create http service fleet, and add these VMs to F5's pool as members.

    - Download :download:`f5-vm.json <https://github.com/panlm/NTNX/raw/master/calm/blueprints/f5-vm.json>`, and launch it.
    - You could execute **scaleout** action to expand fleet as you needed.

    .. figure:: images/f5-vm-bp.png

Settings in F5
--------------

- After blueprint launched, we will see 2 VMs in pool.

    .. figure:: images/f5-3.png

- Let's start to forward F5 logs to ELK for real time analysis, this will be more and more interesting.

    .. figure:: images/f5-1.png

- Enable more customized information for each session and logger it. We use *irules* in F5 to record the start time and end time for each session and logger them.

    .. figure:: images/f5-2.png

More in Kibana
--------------

- More and more logs come in, littery every session should have a log, we have 500 session connect to F5 concurrently, each session will execute 0-5 seconds.

    .. figure:: images/kibana-f5-1.png

    - just focus on highlight part, it's a log from F5, log format just like the irules we defined previous

- This time, we do not collector logs only, we try to parse log with **logstash** and separate useful field for coming analysis. In this log line, we will capture the last number in last round brackets as **session_ms**, it is the session drution time. 

- Goto **Metric** page

    - In **Settings** page, ensure **Metric indices** points to `logstash-*`

        .. figure:: images/kibana-f5-2.png

    - Click **Apply** at the bottom of page to save.

- Goto **Metrics Explorer** page, select field name **session_ms**

    .. figure:: images/kibana-f5-3.png

- Click **Alerts** from top-right corner --> **Create Alert**

    .. figure:: images/kibana-f5-4.png
        :width: 70 %

- You could go to **Management** --> **Alerts and Actions** to check all alert you set. 

    .. figure:: images/kibana-f5-5.png

- I have set 2 alerts, one for average session_ms is above 4000, the other one for max session_ms is above 10000.

    .. figure:: images/kibana-f5-5-1.png
        :width: 70 %

- Alert generated.

    .. figure:: images/kibana-f5-6.png

- If you have advanced license for ELK, you could trigger **Mail/Slack Notification** or **Webhook** by defined alerts







Post-credits Scenes
+++++++++++++++++++

- separate useful column from log to new field with logstash. 

    - reference: `https://medium.com/statuscode/using-custom-regex-patterns-in-logstash-fa3c5b40daab`

    .. code-block:: 

        input {
        udp {
            port => 10514
            type => syslog
        }
        }

        filter {
        if "Session" in [message] {
            grok {
                match => {
                    "message" => "(?<part1>.*]): (?<part2>.*\>): Session from \(%{GREEDYDATA:ipaddress}:%{GREEDYDATA:port}\), time to response\(ms\): \(%{GREEDYDATA:session_ms}\)"
                }
            }
        } else {
            mutate { add_field => { "session_ms" => "-1" } }
        }
        mutate { convert => [ "session_ms", "integer" ] }
        }

        output {
        elasticsearch { hosts => [ "localhost:9200" ] }
        stdout { codec => rubydebug }
        }

- use painless script to do simular, but field created by painless script could not be indexed.

    .. code-block:: 

        if ( params['_source']['message'] =~ /Session/ ) {
            def m = params['_source']['message'];
            int a1 = m.lastIndexOf('(');
            int a2 = m.lastIndexOf(')');
            if (a1 > 0 && a2 > 0) {
                return Integer.parseInt(m.substring(a1+1,a2));
            } else {
                return -1;
            }
        } else {
            return -2
        }




