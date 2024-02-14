---
title: File Inclusion
date: 2024-02-10 20:00 
categories: [Path Traversal]
tags: [Local File Inclusion (LFI)]
author: jamarapo
---

## Local File Inclusion
A dynamic web page is a web page that includes content that is updated regularly. Furthermore, these pages contain web contents that need to be static, for example footer or navigation bar. When a user navigates to another part of the web page, navegator updates content by reading a specific file with a URL param. For example:  /index.php?page=about. LFI vulnerabilities may trigger other vulnerabilities and risks.

In some languages, the paramater language may be changed to read other files, accesible throught LFI and show code files in front page. 


## Language solutions 
https://docs.fluidattacks.com/criteria/vulnerabilities/123/

LFI is a secondary-order-attack beacause we can pull a file with a value that we control indirectly for example change username with etc/passwd avatar and then exploit with other vulnerability.

## Lab 1
![alt text](../assets/img/posts/File%20Inclusion/image.png)

![alt text](../assets/img/posts/File%20Inclusion/image-1.png)

## Encoder
Web applications use URL encoders to prevent LFI. In spite of some versions were vulnerable to this type of attack, we may find strategies to pass directory paths. 

## Valid Paths
Web browser block LFI but, there are some valid paths that allows access to it. In combination with an invalid path we exploit LFI.

## Lab 2
For this lab have been used Ffuf for fuzzing the etc/passwd directory. With the parameter '-mr' we can find the responses with a word or regular expression.
Using the parent directory languages/*
allows LFI.

![alt text](../assets/img/posts/File%20Inclusion/3.png)

![alt text](../assets/img/posts/File%20Inclusion/1.png)

![alt text](../assets/img/posts/File%20Inclusion/2.png)


The flag.txt was finded in the same directory.

---
- *NOTE*

In spite of SecLists repository of HTB pwned machine and the repository of KaliLinux are apparently equal, the version of HTB was not updated. For that reason, is crucial to clone direclty the repository that we will use and worldlists be the same.

---

## PHP Wrappers
Can extend LFI attacks and is used for access Input/Output streams which could be favorable to execute systems commands. 

- **resource**: With this parameter we can specify what stream we will apply the filter.
  
- **read**: With this parameter we can filter input file so we can detail what filter we will use on our resource.
  
There are disctint types of filters: String Filters, Conversion Filters, Compression Filters, and Encryption Filters.

Once we have potencial PHP files fuzzed we will grab files through base64 encoder that allows extract the file. For this way, the result did not empty.
convert.base64-encode.

## Lab 3

In this file firt we fuzzed the webpage finding .php files that exists and return 200 but not showed nothing in the body. Then we encode the using PHP wrapper "language=php://filter/read=convert.base64-encode/resource=" for grab the file in format base64 in the reponse body.

![alt text](../assets/img/posts/File%20Inclusion/4.png)

![alt text](../assets/img/posts/File%20Inclusion/5.png)

![alt text](../assets/img/posts/File%20Inclusion/6.png)

![alt text](../assets/img/posts/File%20Inclusion/7.png)