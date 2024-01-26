// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/add-country-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    let namespace = event.secrets.ID_TOKEN_NAMESPACE || '';
    if (namespace && !namespace.endsWith('/')) {
        namespace += '/';
    }

    if (event.request.geoip) {
        api.idToken.setCustomClaim(
            namespace + 'country',
            event.request.geoip.countryName
        );
        api.idToken.setCustomClaim(
            namespace + 'timezone',
            event.request.geoip.timeZone
        );
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
