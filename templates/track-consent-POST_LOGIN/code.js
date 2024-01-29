// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/track-consent-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * See https://auth0.com/docs/compliance/gdpr/features-aiding-compliance/user-consent/track-consent-with-lock for more information
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    const { consentGiven } = event.user.user_metadata || {};

    // short-circuit if the user signed up already
    if (consentGiven) {
        return;
    }

    // first time login/signup
    api.user.setUserMetadata('consentGiven', true);
    api.user.setUserMetadata('consentTimestamp', Date.now());
    return;
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
