---
title: Server-Side Request Forgery
date: 2024-03-01 20:00 
categories: [Path Traversal]
tags: [HTTP, POST, Server]
author: jamarapo
---

## Server-Side Request Forgery
Server-side request forgery is a web security vulnerability enabling an attacker to induce the server-side application to make requests to an unintended destination. For example, an e-commerce website that consumes an API for retrieving the stock data could be modified to get no authorized information for the local server or information that requires authorization, but the request is not external, which means the request can bypass this security measure. "http://localhost/admin".


Note that access control checks might be implemented in a different component, such as a reverse proxy or load balancer, that sits in front of the application server. When a connection is made back to the server, the check is bypassed.

For disaster recovery purposes, the application might allow administrative access without logging in, to any user coming from the local machine. This provides a way for an administrator to recover the system if they lose their credentials. This assumes that only a fully trusted user would come directly from the server. The administrative interface might listen on a different port number to the main application, and might not be reachable directly by users.

![alt text](/assets/img/posts/SSRF/image-2.png)

![alt text](/assets/img/posts/SSRF/image.png)

![alt text](/assets/img/posts/SSRF/image-1.png)


 In some cases, the application server is able to interact with back-end systems that are not directly reachable by users. These systems often have non-routable private IP addresses. The back-end systems are normally protected by the network topology, so they often have a weaker security posture. In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.

In the previous example, imagine there is an administrative interface at the back-end URL https://192.168.0.68/admin.

## LAB2

![alt text](/assets/img/posts/SSRF/image-4.png)

![alt text](/assets/img/posts/SSRF/image-3.png)

![alt text](/assets/img/posts/SSRF/image-6.png)

![alt text](/assets/img/posts/SSRF/image-5.png)