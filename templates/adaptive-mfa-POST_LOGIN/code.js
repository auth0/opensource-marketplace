/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/adaptive-mfa-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // Decide which confidence scores should trigger MFA, for more information refer to
    // https://auth0.com/docs/secure/multi-factor-authentication/adaptive-mfa/customize-adaptive-mfa#confidence-scores
    const promptConfidences = ['low', 'medium'];

    // Example condition: prompt MFA only based on the NewDevice
    // confidence level, this will prompt for MFA when a user is logging in
    // from an unknown device.
    const confidence =
        event.authentication?.riskAssessment?.assessments?.NewDevice
            ?.confidence;
    const shouldPromptMfa =
        confidence && promptConfidences.includes(confidence);

    // It only makes sense to prompt for MFA when the user has at least one
    // enrolled MFA factor.
    const canPromptMfa =
        event.user.multifactor && event.user.multifactor.length > 0;
    if (shouldPromptMfa && canPromptMfa) {
        api.multifactor.enable('any', { allowRememberBrowser: true });
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
