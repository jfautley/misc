This repo contains a collection of use(ful|less) scripts I've not seen fit to put elsewhere.

checkaccess.c: Check that a user is able to establish a PAM account context.
             : This is designed to check that a user is permitted access to a particular PAM
             : service (typically, and by default the "login" service). A good use for this is
             : checking pam_access permissions (for example, where security.conf contains
             : netgroups).


All code in this repository is licensed under the MIT license, unless otherwise stated.
