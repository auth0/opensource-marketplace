/**
 * Handler that will be called during the execution of a Password Reset / Post Challenge Flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/active-directory-groups-PASSWORD_RESET_POST_CHALLENGE ---
 *
 * @param {Event} event - Details about the post challenge request.
 * @param {PasswordResetPostChallengeAPI} api - Interface whose methods can be used to change the behavior of the post challenge flow.
 */
exports.onExecutePostChallenge = async (event, api) => {
    // ensure that the allowed group is configured
    const groupAllowed = event.secrets.ALLOWED_GROUP;
    if (!groupAllowed) {
    return api.access.deny('Invalid configuration');
    }

    // get the users groups
    let groups = event.user.groups || [];
    if (!Array.isArray(groups)) {
    groups = [groups];
    }

    // if the allowed group is not one of the users, deny access
    if (!groups.includes(groupAllowed)) {
    return api.access.deny('Access denied');
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
