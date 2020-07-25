# WebSec

Author: Navid Kagalwalla

This is a documentation on various web application attacks that I have come across during web security labs and bug bounty hunting.

## Account Takeover

This is a type of vulnerability that allows hackers to take full control of the user's account without any need for a password by finding the flaws in the application. 

Try the following methods to try to get this vulnerability:

 - Play and Tamper 'Forgot Password' implementation by 
 1) Changing email field, adding extra email field in the request
 2) Changing mobile number if password can be reset using it 
 3) Password Reset Poisoning which consists of capturing the forgot password request and adding X-Forwarded-Host which results in user getting a tampered password reset token. Read more here - https://medium.com/@vbharad/account-takeover-through-password-reset-poisoning-72989a8bb8ea 
 
 - Play with the 'Sign Up' feature
 1) Check if account is verified using email id after signup
 
 - Brute Force the 'Login'
 1) After knowing the email id of victim, password can be brute forced. Check for weak password policy.
 
## EXIF Geolocation Data Not Stripped from Uploaded Images

EXIF is short for Exchangeable Image File, a format that is a standard for storing interchange information in digital photography image files using JPEG compression. 
When a user uploads an image in example.com, the uploaded image’s EXIF Geolocation Data does not gets stripped. As a result, anyone can get sensitive information of example.com users like their Geolocation, their Device information like Device Name, Version, Software & Software version used etc.

Try the following to try to get this vulnerability:

- Use any upload functionality on a website to upload an image which has EXIF Data present. After uploading, right click to get image url. Check this image url with http://exif.regex.info/exif.cgi. If EXIF Data still present, it is a vulnerability.

## Failure to invalidate session - On password change, password reset, logout

All other sessions which are logged in must be invalidated after password change, reset or on logout. 
If an attacker has a user's password, he/she can log in and even after the legitimate user changes password/ resets password, the attacker's session will still be active. 

Try the following:
1) Create an account having email address "example@x.com".
2) Now logout and ask for password reset link. Don't use the password reset link sent to your mail address.
3) Login using the same password back and update your email address to "example123@x.com" and verify the same. Remove "example@x.com".
4) Now logout and use the password reset link which was mailed to "example@x.com" in step 2.
5) Password will be changed.

This is a vulnerability because of the following attack scenario. If my email account is compromised and the attacker asks for password reset link for my account. The legitimate user gets to know and changes his email address. The user now thinks he is safe.  But the hacker can still use the old password reset links (which he had never used for single time) which were sent to my old email address. The account is now compromised again.

## Mail Server Misconfiguration

This is a server security misconfiguration due to missing SPF/DMARC on email domain which can lead to social engineering attacks.
Steps for this:
1) Open this url http://emkei.cz/
2) Type In the ''From email'' field the vulnerable website's email id.
3) After That Send to the victim email like victim@x.com in ''To'' field.
4) Write other details what you want and send it to victim email. 
5) Victim will recieve an email from the website.

## No Rate Limiting on Form

A rate limiting algorithm is used to check if the user session (or IP-address) has to be limited based on the information in the session cache.
In case a client made too many requests within a given time frame, HTTP-Servers can respond with status code 429: Too Many Requests.

If no rate limiting is present it can DoS attacks and mass email load on servers.

## Cross Origin Resource Sharing Misconfiguration

An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the policy. The policy is fine-grained and can apply access controls per-request based on the URL and other features of the request.
Trusting arbitrary origins effectively disables the same-origin policy, allowing two-way interaction by third-party web sites. Unless the response consists only of unprotected public content, this policy is likely to present a security risk.
If the site specifies the header Access-Control-Allow-Credentials: true, third-party sites may be able to carry out privileged actions and retrieve sensitive information. Even if it does not, attackers may be able to bypass any IP-based access controls by proxying through users' browsers.

Check https://hackerone.com/reports/470298 for implementation.

## Open Redirect

A web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a Redirect. This simplifies phishing attacks. An http parameter may contain a URL value and could cause the web application to redirect the request to the specified URL. By modifying the URL value to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials. Because the server name in the modified link is identical to the original site, phishing attempts have a more trustworthy appearance.

User can be redirect to malicious site using for example : https://www.example.com/redirect?url=http://bing.com

## Token Leakage Via Referrer

If a user opens the link of reset password and than click on any external links within the reset password page its leak password reset token in referer header.

Steps:

1) Open Password reset page from email. 
2) Click on any social media link(on follow us section)
3) Intercept the request(I have used burp suite) 
4) You can see the link for reset password in referrer

It allows the person who has control of particular site to change the user's password (CSRF attack), because this person knows reset password token of the user.

## Violation of Secure Design Priciples

Password check must be done when deleting account, disabling 2FA, changing email address. 

## XSS

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.

Try running payloads from https://github.com/pgaijin66/XSS-Payloads on all available input points. Self XSS can be elevated to CSRF or Reflected XSS to make it more severe.

## OAuth Misconfiguration

OAuth 2.0 is an authorization framework for Web Application. It validates the identity of a user to the website which requested it without disclosing passwords to the website. Vulnerability in OAuth flow leads to takeover of victim account . An attacker can take over the account of the victim.
For implementation see https://medium.com/@GAYA3_R/account-takeover-using-oauth-misconfiguration-3fab424317c1

## IDOR

IDOR stands for Insecure Direct Object Reference and it is a vulnerability in which an attacker can access sensitive information by making unauthorized references.
Types of IDOR

Blind IDOR: The type of IDOR in which the results of the exploitation cannot be seen in the server response. For example modifying other user private data without accessing it.

Generic IDOR: The type of IDOR in which the results of the exploitation can be seen in the server response. For example accessing confidential data or files belonging to another user.

IDOR with Reference to Objects: Used to access or modify an unauthorized object. For example accessing bank account information of other users by sending such a request →example.com/accounts?id={reference ID}

IDOR with Reference to Files: Used to access an unauthorized file. For example a live chat server stores the confidential conversations in files with names as incrementing numbers and any conversation can be retrieved by just sending requests like this →example.com/1.log, example.com/2.log, example.com/3.log and so on.

For implementation see https://medium.com/@corneacristian/top-25-idor-bug-bounty-reports-ba8cd59ad331



















