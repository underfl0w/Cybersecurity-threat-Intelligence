---
author:
- |
    Jurjen de Jonge\
    \
    Hogeschool van Amsterdam
title: Threat intelligence week 5
---

Malicious PDF Analysis
======================

Analyzing a PDF file within Kali linux
--------------------------------------

### Getting the PDF version number

I've used a tool called pdfinfo to gather some information about the
pdf. It ran like \"pdfinfo ITservice2015.pdf\" and generated the
following data.

![Using PDFinfo to gather
information[]{label="Fig:PDFinfo"}](pdfversion.png){#Fig:PDFinfo}

The file is a pdf of version 1.3

### How many EOF exists

There are two %%EOF in the file between object 135 & object 136. I used
grep on the output of the pdf-parser to quickly see how many times it is
found inside this PDF.

![Grepping to see how many %%EOF
exist[]{label="Fig:EOFgrep"}](eof.png){#Fig:EOFgrep}

![Finding the first %%EOF[]{label="Fig:EOF1"}](firsteof.png){#Fig:EOF1}

The second %%EOF is findable the end of the document as obj 2 0 And has
the tag startxref 638218

![Finding the second
%%EOF[]{label="Fig:EOF2"}](secondeof.png){#Fig:EOF2}

### Javascript within the PDF

There is a refference to javascript within the document tags. Within obj
140 javascript is being referenced. The javascript exports a dataobject
towards disk. This document is named Document2 and will be called
Document2.pdf.

![Attackers using javascript to drop an seconds
pdf[]{label="Fig:EOF2"}](javascript.png){#Fig:EOF2}

### Launch tag 

Using the launch tag within a pdf file enables the creator to launch
software. In this case it's used to execute cmd.exe.\
It performs a couple checks to see if the dropped Document2.pdf is found
and opens it. It will try to trick the user in by hiding the warning
message.

![Launching
Document2.pdf[]{label="Fig:pdfexploit"}](launchex.png){#Fig:pdfexploit}

### PDF attack within the Cyber kill chain

Depending on the way this document is viewed it could be placed in the
Exploit part or the Delivery part. One could say that the payload is
being delivered using a the pdf file. I would say it's the Exploit part.
The pdf is being used to execute code / commands on the targeted
computer.

YARA
====

Starting with YARA
------------------

### What is YARA

YARA is developed by Victor Alvarez, working at Virustotal. It stands
for \"YARA: Another Recursive Ancronym, or Yet Another Ridiculous
Acronym.\" [^1] It is mostly being used to identify and clasify malware
using textual or binary patterns. Each rule will consist of strings and
some boolean logic to determine the logic. [^2]

``` {frame="single"}
rule silent_banker : banker
{
    meta:
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
```

### What is C2?

C2 stand for C&C which in turn stands for Command & control. Which is
the server that is being used to send call backs to. Each agent will
register himself to a C2 waiting for additional tasks to perform. An
example of this is the meterpreter listener and the reverse https
payload.

### The size of the memory dump

The size is 4321MB.

![Looking at the filesize using ls.
[]{label="Fig:pdfexploit"}](size.png){#Fig:pdfexploit}

### Analyzing the memory dump

Two domain, systeminfou48.ru and infofinanciale8h.ru where found within
the memory dump.

![Two domains found using the yara
rule[]{label="Fig:yarafounding"}](c2yara.png){#Fig:yarafounding}

``` {frame="single"}
rule Russia_C2
{
    strings:
        $A="systeminfou48.ru"
        $B="infofinanciale8h.ru"
        $C="helpdesk7r.ru"
    condition:
        $A or $B or $C
}
```

Two string will be found when scanning through the memory dump.
defrag.vbs & HWAWAWAWA.

![Finding the two Strings, defrag.vbs multiple
times.[]{label="Fig:YaraStrings"}](stringsyaraa.png){#Fig:YaraStrings}

![The merged Yara files scanning the memory
dump[]{label="Fig:YaraStrings"}](final.png){#Fig:YaraStrings}

Questions about YARA
--------------------

### Why would I use YARA

I would use YARA to automatically analyze files for common malicious
aspects. Finding resources that are passing through the network or
hiding in files.

I could also be used to as forensics tool, seeing how far a actor got
inside of the network.

### Alternatives to YARA

An alternative I could come up with is PEiD, It uses signatures to
detect packers, cryptors and compilers for PE files. This way malware
researcher can easily detect what they are working with. Of course these
rules could also be ported towards YARA.

[^1]: https://twitter.com/plusvic/status/778983467627479040

[^2]: https://virustotal.github.io/yara/
