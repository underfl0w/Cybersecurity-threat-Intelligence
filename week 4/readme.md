---
author:
- |
    Jurjen de Jonge\
    \
    Hogeschool van Amsterdam
title: Threat intelligence week 4
---

DNS recon
=========

I will start by asking the Cisco DNS server for information related to
the cisco.com domain. Here I would obtain a little overview of publicly
listen domains.

dnsrecon.py
-----------

The first step I did to find IP addresses was using dnsrecon.py, this
gave me a list of different domains and ip's associated with cisco.com.
This tool automatically finds dns records, tries DNS zone transfer and
other various methods to find domains and associated ip addresses.

![XML output by
DNSrecon.[]{label="Fig:DNSrecon"}](dnsrecon.png){#Fig:DNSrecon}

As seen in Figure 1.1, the had been able to collect data from the DNS
servers of cisco, sadly it wasn't possible to collect all the ip's.

Shodan.io
---------

Searching for the domain \"cisco.com\" including the Cisco systems
allowed me to find 228 ip addresses associated with the cisco domain.

![Search results Shodan on Cisco.com
domain[]{label="Fig:Shodanresults"}](shodan.png){#Fig:Shodanresults}

Shodan found a lot of ip's associated with Cisco.com, this could have
been done by reverse DNS lookup. Asking each IP address for it's domain
information. This method could also be used from your own computer but
would be slower. I would advice to look at which IP-blocks are owned by
Cisco and perform the reverse DNS lookup on those addresses.

##### Stopping DNS recon

It's hard to detect these kind of attacks. But when one computer is
accessing a lot of domains and IP's in a short period of time would be
an indicator of an attack. IPS could kick in and block the IP address
from accessing any resources from the company.

##### Detecting

It would be difficult detecting the attack when it's performed using
Shodan as those IP's have already been indexed by Shodan and no
additional connections are being made towards the Cisco network. Regular
DNS requests are also common and should not be marked as mallicious.

Payload
=======

Gaining access to a machine
---------------------------

Using the commands given it was easy to create the payload

![Weaponization using
msfvenom[]{label="Fig:Creatingmeterpreterpayload"}](weapon1.png){#Fig:Creatingmeterpreterpayload}

Then creating a listener using the msfconsole and the multi handler
epxloit also following the commands given in the pdf. The file will be
downloaded and executed on the Windows machine. That would create a
session within the MSFconsole allowing us to execute commands on the
Windows machine.

![Creating the
handler[]{label="Fig:CreatingtheListner"}](weapon2.png){#Fig:CreatingtheListner}

Then executing several commands on the Windows machine and trying to
migrate the process towards an system user process or different. It
wasn't possible for me to migrate towards System as the user had
insufficient privileges.

![Migrating towards explorer process NOTE: failed to migrate towards
system
process[]{label="Fig:MigrateExplorerFailedSystemUser"}](migrate.png){#Fig:MigrateExplorerFailedSystemUser}

Virustotal scan
---------------

Interesting enough encrypting the payload using the msfvenom created a
higher detection rate than without encryption.

![Virustotal scan with encrypted payload having higher detection
rate[]{label="Fig:Virustotaldetection"}](virus.PNG){#Fig:Virustotaldetection}

![Creation of the encoded
payload[]{label="Fig:encodemeterpreterpayload"}](encodecreate.png){#Fig:encodemeterpreterpayload}

Evilgrade attack
================

A Windows 7 computer has been running an old version of Notepad++. The
user updated the software using the build in update function. Sadly this
function is insecure as it downloads the executable over a http
connection. This allows hackers to intercept the download and replace it
with malware. I had to trouble shoot the system before figuring out what
why the evilgrade was not working. And I was not able to replicate this
attack for a second time.

![Starting of the ettercap MITM DNS spoofing
attack[]{label="Fig:ettercapevilgradeattackmitm"}](ettercap.png){#Fig:ettercapevilgradeattackmitm}

Ettercap is being used to poison the network using a dns spoofing. This
attack makes the clients use the fake dns lookup provided by attacker.
In this case it's used to send sourceforge.net towards the attacking
machine.

![Evilgrade replacing the executable for a malicious meterpreter
executable[]{label="Fig:Evilgradeexereplace"}](evilgrade.png){#Fig:Evilgradeexereplace}

Evilgrade is used to act as web & dns server. It sees the incoming
request for sourceforge, accepts the connection and responds by sending
back an \"update\" that in this case is a reverse\_tcp shell.

![Meterpreter session started after \"update\" was
installed[]{label="Fig:Meterpreterevevilgradeettercap"}](evilshell.png){#Fig:Meterpreterevevilgradeettercap}

Notepad++ trusts that the update is actually a update and executes the
executable that it received resulting in a malware infection.

SSLstrip 
=========

In the lab it is being requested that a microsoft website is used to
test SSLstrip. Luckily this doesn't work any more on that website. The
HvA webpage still is allows non https requests to be made to the
webserver. This means that SSLstrip is still able to redirect older
browsers towards the non ssl encrypted version of the website.

![SSL strip being used on the HvA website. User credentials are visible
and
highlighted[]{label="Fig:SSLSTRIPHVAwebsite"}](sslstriphva.png){#Fig:SSLSTRIPHVAwebsite}
