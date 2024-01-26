/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/guardian-multifactor-authorization-extension-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // ensure the user has verified their email
    if (!event.user.email_verified) {
        return api.access.deny('Email not verified');
    }

    // ensure the MFA roles are configured
    const mfaRoles = event.secrets.MFA_ROLES?.split(',')
        .map((role) => role.trim().toLowerCase())
        .filter((role) => role);
    if (!mfaRoles) {
        return api.access.deny('Invalid configuration');
    }

    // get the list of user roles that require MFA
    const userMFARoles = event.authorization?.roles.filter((role) =>
        mfaRoles.includes(role)
    );

    // if there are roles that require MFA then enable guardian MFA
    if (userMFARoles && userMFARoles.length) {
        // set allowRememberBrowser to force MFA every time
        api.multifactor.enable('guardian', { allowRememberBrowser: true });
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
