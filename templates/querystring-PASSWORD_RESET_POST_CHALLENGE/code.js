/**
 * Handler that will be called during the execution of a Password Reset / Post Challenge Flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/querystring-PASSWORD_RESET_POST_CHALLENGE ---
 *
 * @param {Event} event - Details about the post challenge request.
 * @param {PasswordResetPostChallengeAPI} api - Interface whose methods can be used to change the behavior of the post challenge flow.
 */
exports.onExecutePostChallenge = async (event, api) => {
    // ensure the stored query key name is valid
    if (!event.secrets.QUERY_KEY) {
        return api.access.deny('Invalid configuration');
    }
    // ensure the stored query key value is valid
    if (!event.secrets.QUERY_VALUE) {
        return api.access.deny('Invalid configuration');
    }
    // this is a generic example of accessing the query string
    const queryValue = event.request.query[event.secrets.QUERY_KEY];
    if (queryValue === event.secrets.QUERY_VALUE) {
        // this is a specific PASSWORD_RESET_POST_CHALLENGE example of using the query string to trigger setting custom claims
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
