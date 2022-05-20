> NOTE: this repository is obsolete; this code here depends on pam-python, which is hardly supported any more, and should not be considered safe
> for production use.  
> 
> The pam-websso functionality has been rewritten from scratch and is now available in [SURFscz/pam-weblogin](https://github.com/SURFscz/pam-weblogin)

# pam-websso
(SAML) WebSSO PAM Module

This module consists of two parts: A PAM module and a websso daemon.
The PAM module runs on the host(s) that is supposed to accept SAML WebSSO login.
WebSSO Daemon runs on a server that handles SAML authentication (SP).

Edit pam_websso.json to configure remote host and port of WebSSO Daemon.
websso_daemon.json should contain configuration for three ports: the clients port (on which the PAM modules connect) the Command port (on which authentication requests can manually be authenticated for test purposes). This port will only bind to localhost for security reasons.
The web port is the HTTP interface that will serve the SAML SP and SSO URL. The URL should contain a %s to substitute the requested nonce. The rest of the configuration file is OneLogin Python SAML configuration. See https://github.com/onelogin/python-saml.

Add these lines to /etc/pam.d/sshd

```
+ auth sufficient pam_python.so /opt/pam-websso/pam_websso.py
  # Standard Un*x authentication.
  @include common-auth

+ session required pam_mkhomedir.so umask=0022 skel=/etc/skel
  # Standard Un*x session setup and teardown.
  @include common-session
```

Authentication flow

1. User starts ssh process using commandline ssh command:
```$ ssh user@vm.server.org```
2. SSH will consult that pam_websso module for authentication
3. pam_websso will contact websso_daemon, send a pin and receive a unique nonce, keeps connection open
4. pam_websso displays the SAML SP URL+nonce challenge to the user (URL is served by websso_daemon)
5. User may press <enter> now, to skip websso authentication, or
6. User opens URL and authenticates at IdP of choice
7. websso_daemon relates SAML authentication to requested URL+nonce, shows authentication result + pin and informs PAM client of authenticated user and result.
8. pam_websso receives user and authentication result line
9. pam_websso checks for ```<RESULT>=="SUCCESS"```, ```<user>==user``` and ```<pin>=pin``` returns ```PAM_SUCCESS``` if correct
10. In all other cases pam_websso returns ```PAM_AUTH_ERR```.
11. SSH will check if user exists on local system.
