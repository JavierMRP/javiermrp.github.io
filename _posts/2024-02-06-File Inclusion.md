---
title: File Inclusion
date: 2024-02-07 20:00 
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

