/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/querystring-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // ensure the query key is valid
    if (!event.secrets.QUERY_KEY) {
        return api.access.deny('Invalid configuration');
    }
    //ensure the query value is valid
    if (!event.secrets.QUERY_VALUE) {
        return api.access.deny('Invalid configuration');
    }

    // this is a generic example of accessing the query string
    const queryValue = event.request.query[event.secrets.QUERY_KEY];
    if (queryValue === event.secrets.QUERY_VALUE) {
        // this is a specific POST_LOGIN example of using the query string to trigger setting custom claims
        const {
            CUSTOM_CLAIM_NAME: customClaimName,
            CUSTOM_CLAIM_VALUE: customClaimValue,
        } = event.secrets;
        // ensure the custom claim name secret is valid
        if (!customClaimName) {
            return api.access.deny('Invalid configuration');
        }
        // ensure the custom claim value is valid
        if (!customClaimValue) {
            return api.access.deny('Invalid configuration');
        }
        api.idToken.setCustomClaim(customClaimName, customClaimValue);
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
