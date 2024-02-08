---
title: Server-side vulnerabilities
date: 2024-02-07 20:00 
categories: [Path Traversal]
tags: [Local File Inclusion (LFI), Vertical Scalation, Horizontal Scalation]
author: jamarapo
---


## Path traversal 
Path traversal is a vulnerability in which the attacker uses URL path parameters commonly used for backend services and API's in web pages. With these parameters, the attacker can manipulate the request to grab other files.

- **Lab: File path traversal, simple case**:  This lab contains a path traversal vulnerability in the display of product images. To solve the lab, retrieve the contents of the /etc/passwd file. 

  
  ![alt text](../assets/img/posts/image.png)
  In this file, the user accounts on the system are shown, each with its user name, user ID, group ID, description, home directory and shell. The lines are in the standard format of the /etc/passwd file on Unix/Linux systems.
  ![alt text](../assets/img/posts/image-1.png)


## Vertical Scalation
When a user does actions and gains access to restricted resources of one user that are in the same level. 
A typical example of this scalation is when a user can enter admin files through open admin urls, APIs and services.

- **Lab: Unprotected admin functionality**: This lab has an unprotected admin panel.
Solve the lab by deleting the user carlos. 

![Desktop View](../assets/img/posts/image-4.png)

![alt text](../assets/img/posts/image-5.png)

- **Lab: Unprotected admin functionality with unpredictable URL**:  This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.
Solve the lab by accessing the admin panel, and using it to delete the user carlos. 

![alt text](../assets/img/posts/image-6.png)
This script verify that the user is admin but the URL is open to all users regardless of their role.

## Parameter-based access control methods
Applications can save the information of user role in changeable storage or parameters. That allows to user do actions of other role.

- **Lab: User role controlled by request parameter**: This lab has an admin panel at /admin, which identifies administrators using a forgeable cookie. Solve the lab by accessing the admin panel and using it to delete the user carlos. You can log in to your own account using the following credentials: wiener:peter 

![alt text](../assets/img/posts/image-7.png)

![alt text](../assets/img/posts/image-8.png)

## Horizontal Scalation
Happens when a user can access to resources of user that have higest privilages.

Insecure Direct Object Reference (IDOR) vulnerability

The GUIDs (Globally Unique Identifier) can protect to guess the user identifier. However GUID may present in the application.

- **Lab: User ID controlled by request parameter, with unpredictable user IDs**:  This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs. 
To solve the lab, find the GUID for carlos, then submit his API key as the solution.
You can log in to your own account using the following credentials: wiener:peter 

![alt text](../assets/img/posts/image-11.png)

![alt text](../assets/img/posts/image-12.png)

