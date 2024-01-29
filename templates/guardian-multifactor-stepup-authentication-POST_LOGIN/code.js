/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/guardian-multifactor-stepup-authentication-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // confirm if MFA is enabled. For more information on client config, refer to
    // https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication/configure-step-up-authentication-for-web-apps#configure-app
    const isMfa = event.transaction?.acr_values.includes(
        'http://schemas.openid.net/pape/policies/2007/06/multi-factor'
    );

    let authMethods = [];
    if (event.authentication && Array.isArray(event.authentication.methods)) {
        authMethods = event.authentication.methods;
    }

    if (isMfa && !authMethods.some((method) => method.name === 'mfa')) {
        api.multifactor.enable('any', { allowRememberBrowser: false });
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
