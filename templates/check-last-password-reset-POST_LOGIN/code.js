/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/check-last-password-reset-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // ensure the secret is valid
    if (!event.secrets.MAX_PASSWORD_DAYS) {
        return api.access.deny('Invalid configuration');
    }

    // function to calculate the difference (in days) between two dates
    const daydiff = (first, second) => (second - first) / (1000 * 60 * 60 * 24);

    // capture the teimstamp of the last password change or account creation
    const lastPasswordChange =
        event.user.last_password_reset || event.user.created_at;

    // ensure password rotation is configured correctly
    let maxDays;
    try {
        maxDays = Number(event.secrets.MAX_PASSWORD_DAYS);
    } catch {
        return api.access.deny('Invalid configuration');
    }
    if (!maxDays) {
        return api.access.deny('Invalid configuration');
    }

    // if the password is beyond the configured threshold, reject access with a message to change it
    if (daydiff(new Date(lastPasswordChange), new Date()) > maxDays) {
        return api.access.deny('please change your password');
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
