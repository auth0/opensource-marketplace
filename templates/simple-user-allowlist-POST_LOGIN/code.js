// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/simple-user-allowlist-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    if (!event.secrets.ALLOWED_USER_EMAILS) {
        return api.access.deny('missing allowed user emails');
    }

    // Access should only be granted to verified users.
    if (!event.user.email || !event.user.email_verified) {
        return api.access.deny('access denied.');
    }

    const allowedUsers = event.secrets.ALLOWED_USER_EMAILS.split(',')
        .map((email) => email.trim())
        .filter((email) => !!email);
    const userHasAccess = allowedUsers.some(
        (email) => email === event.user.email
    );

    if (!userHasAccess) {
        return api.access.deny('access denied.');
    }
};

/**
 * Handler that will be invoked when this action is resuming after an external redirect. If your
 * onExecutePostLogin function does not perform a redirect, this function can be safely ignored.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
// exports.onContinuePostLogin = async (event, api) => {
// };
