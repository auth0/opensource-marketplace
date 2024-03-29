/**
 * Handler that will be called during the execution of a Password Reset / Post Challenge Flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/simple-user-allowlist-on-a-connection-PASSWORD_RESET_POST_CHALLENGE ---
 *
 * @param {Event} event - Details about the post challenge request.
 * @param {PasswordResetPostChallengeAPI} api - Interface whose methods can be used to change the behavior of the post challenge flow.
 */
exports.onExecutePostChallenge = async (event, api) => {
    // ensure the connection secret is valid
    if (!event.secrets.ALLOW_LIST_CONNECTION) {
        return api.access.deny('Invalid configuration');
    }

    // ensure the list of allowed user email is valid
    if (!event.secrets.ALLOW_USER_EMAILS) {
        return api.access.deny('Invalid configuration');
    }

    // access should only be granted to verified users
    if (!event.user.email || !event.user.email_verified) {
        return api.access.deny('Access denied.');
    }

    // require allow list validation for the configured connection
    if (event.secrets.ALLOW_LIST_CONNECTION === event.connection.name) {
        // determine if this user is in the allowed user email list
        const userHasAccess = !!event.secrets.ALLOW_USER_EMAILS.split(',').some(
            (email) => email.trim() === event.user.email
        );
        // if they are not in the allowed list then deny access
        if (!userHasAccess) {
            return api.access.deny('Access denied.');
        }
    }
};

/**
 * Handler that will be invoked when this action is resuming after an external redirect. If your
 * onExecutePostChallenge function does not perform a redirect, this function can be safely ignored.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PasswordResetPostChallengeAPI} api - Interface whose methods can be used to change the behavior of the post challenge flow.
 */
// exports.onContinuePostChallenge = async (event, api) => {
// };
