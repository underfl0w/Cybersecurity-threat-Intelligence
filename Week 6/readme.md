---
author:
- |
    Jurjen de Jonge\
    \
    Hogeschool van Amsterdam
title: Threat intelligence week 6
---

IoC development
===============

Developing the IOC
------------------

Adding all the given variables to the Mandiant IOCe software was easy to
do.

![Usign the MNdiant IOCe software to create an
IoC[]{label="Fig:IOCEmandiant"}](ioce.png){#Fig:IOCEmandiant}

Adding all the rules is easy, just using the GUI it's very easy to keep
on adding rules and logic to the IoC. A large variety of options are
available to add to the IoC. Seeming to make the software like a
valuable tool.

Sadly when trying to use the rule set made for Mandiant Redline, it will
not reconize the IoC search as something to be found back in the memory
dump that was given to us.

![Error when using the IoC within
RedLine[]{label="Fig:ErrorRedLine"}](analysis.png){#Fig:ErrorRedLine}

Adding up to the rules was again easy to do, but sadly RedLine showed
the same problem with the memory dump as before.

![Adding more rules to the and RedLine failing again to use these
IoC[]{label="Fig:ErrorRedLine"}](moreiocee.png "fig:"){#Fig:ErrorRedLine}
![Adding more rules to the and RedLine failing again to use these
IoC[]{label="Fig:ErrorRedLine"}](again.png "fig:"){#Fig:ErrorRedLine}

About STIX & TAXII
==================

What is STIX?
-------------

Structured Threat Information Expression (STIX) is a format that is used
to share cyber threat intelligence with others. It uses JSON format
where objects are created. There are twelve STIX domain objects. There
objects are linked to each other using the Relationship objects.

This creates a small graph that is easy in use for analyst or processing
with tools.

What is TAXII
-------------

Trusted Automated Exchange of Intelligence Information (TAXII) Is
protocol designed for communicating Cyber threat information (CTI). It
has been specifically designed to transfer STIX. Though TAXII it was
designed specifically for STIX it can be used to transport non STIX
data.

Difference between TAXII client and TAXII server
------------------------------------------------

It seems like the difference between the client and server are like
every other server \<-\> client relationship. The client requests
something from the server and it responeds to that request.

STIX
====

Attack pattern
--------------

The attack pattern is the description of how adversaries try to
compromise targets. It connects towards identity and vulnerability. They
indicate that an attack is targeted towards a certain identity or
vulnerability in a software.

Campaign
--------

The campaign is the grouping of adversarial behavior. It's a set of
malicious activities or attacks against a specif target. Campaigns are
characterized by their objsectives and incidents they cause, targets and
resources they use. They are attributed-to to intrusion-set and
threat-actor. Which actors and the behavior they show. The targets
relationship is identity and vulnerability showing the exploits and type
of targets. Using a certain exploit being used or people targeted from a
specific sector. The uses relationship will be linked to attack-pattern,
malware and tool. This describes how the campaign will go, which actions
will be taken and which malware/tools will be used.

Course of Action
----------------

A description of which actions to take to prevent or respond to an
attack. Relationships are mitigates and related to attack pattern,
malware, tool and vulnerability. Describing how to mitigate them.

Identity
--------

This identifies actual individuals, organizations or groups. The
relationships it has are only reverse relationships.

Indicator
---------

The indicator will describe, the detected kill chain phases, time window
for when the indicator is valid and a pattern to capture detection. The
relationships are indications towards attack-pattern,
campaign,intrusion-set,malware,threat-actor and tool. It described
evidence against the related objects. This could also be secondary
evidence.

Intrusion set
-------------

The intrusion set is grouped set of adversarial behaviors and resources
with common properties and are believed to be done by a single
organization. The set might capture multiple campaigns and share
attributes with known and unknown threat actors. Relationships are
attributed to a threat actor, targets are identity and vulnerability and
uses attack-pattern, malware and tool. All similar to campaign.

Malware
-------

Malware describes malicious code and software according to family and
samples. The relationships are targets, identity and vulnerability.
Malware targeting a specific sector or using a specific exploit. uses
relationship is tool which documents that the malware is related to a
tool. And variant of which describes the variant of a certain type.
(TorrentLocker is a variant of CryptoLockers)

Observed Data
-------------

Describes what information was observed on a system. A file, IP-address,
network connection or registry key can all be observerd. It does not
bring any intelligence with it, just the fact that it was seen. It does
not have any relationships.

Report
------

Reports are collections of threat intelligence focused on one or more
topics. A description of threat actors, malware or attack technique. It
does not have any specif relationships. The relationships it has are
linked to anything that is related the what is written about in the
report.

Threat actor
------------

These are groups, organizations or individuals that operate with
malicious intent. They are characterized by their motives, capabilities,
goals, sophistication level, past activities, resources they have access
to, and their role in the organization. The relationships are attributed
to with identity which describes their real identity, impersonates with
identity and describes whom is being impersonated, targets with identity
and vulnerability which describes the actors use of exploits and
targets, uses towards attack pattern, malware and tool and describes
typical behavior, tools and malware being used.

Tool
----

Tools are legitimate software that can be used for attacks. The tools
have legitimate purposes on systems for power users, admins and even
normal users. it characterizes the properties of the software and how
they are used in an attack. It has a relationship to targets with
identity and vulnerability which again describes an exploit or specific
target.

Vulnerability
-------------

The vulnerability describes a mistake in software that can be used by an
attacker to gain access to or disrupt a system. It does not have any
outgoing relationships.
