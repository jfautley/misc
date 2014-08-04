/* checkaccess: Confirm that a user 'should' be permitted login access to a
 * system.
 *
 * This is designed to confirm that a specific user account would be permitted
 * access in situations where pam_access is in use.
 *
 * This program is originally based on code from:
 *    http://www.linux-pam.org/Linux-PAM-html/adg-example.html
 *
 * Originally written by "AGM" and "kukuk"
 * Modified extensively by Jon Fautley <jon@dead.li>
 *
 * Only tested on RHEL6, compile with "gcc -o checkaccess checkaccess.c -lpam"
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    pam_handle_t *pamh = NULL;
    int retval, exitcode;
    const struct pam_conv conv;
    const char *user;
    const char *pam_service = "login";

    if(argc < 2 || argc > 3) {
      fprintf (stderr, "Usage: %s <username>\n", argv[0]);
      exit (1);
    }

    // Get our user account from the command line
    user = argv[1];

    // Someone has used given us a service name, too. This feature is
    // intentionally undocumented.
    if (argc == 3) {
      pam_service = argv[2];
    }

    // Start our PAM transaction, by default we pretend we're the "login" service
    retval = pam_start(pam_service, user, &conv, &pamh);

    // Check we've been able to start PAM correctly
    if (retval != PAM_SUCCESS) {
      fprintf (stderr, "%s: Unable to start PAM session.", argv[0]);
      exit(1);
    }

    // We've got a valid PAM session, lets call out to acct_mgmt to try and get
    // an account context. According to the PAM docs, we shouldn't really call
    // this without a previous call to pam_authenticate, but given what we're
    // testing for, we're skipping that step and determining our access rights
    // based on the PAM return code from this call.
    retval = pam_acct_mgmt(pamh, 0);

    // The return from the previous function can be one of PAM_SUCCESS,
    // PAM_AUTH_ERR, PAM_NEW_AUTHTOK_REQD, PAM_PERM_DENIED, PAM_USER_UNKNOWN -
    // assume that anything _other than PAM_PERM_DENIED and PAM_USER_UNKNOWN
    // are "success" in this context.
    if (retval == PAM_PERM_DENIED) {
      // Permission denied
      fprintf(stdout, "User %s is NOT permitted %s access on this host [%d]\n", user, pam_service, retval);
      exitcode = 1;
    } else if (retval == PAM_USER_UNKNOWN) {
      // Unknown user
      fprintf(stdout, "User %s is unknown\n", user);
      exitcode = 1;
    } else {
      fprintf(stdout, "User %s is permitted %s access on this host [%d]\n", user, pam_service, retval);
      exitcode = 0;
    }

    if (pam_end(pamh,retval) != PAM_SUCCESS) {
        pamh = NULL;
        fprintf(stderr, "%s: failed to close PAM session?\n", argv[0]);
        exit(1);
    }

    // Return an exit code indicating the likelyhood of success/failure
    return (exitcode);
}
