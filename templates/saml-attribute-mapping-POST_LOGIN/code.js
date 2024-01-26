// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/saml-attribute-mapping-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    api.samlResponse.setAttribute(
        'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier',
        event.user.user_id
    );

    if (event.user.email) {
        api.samlResponse.setAttribute(
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            event.user.email
        );
    }

    if (event.user.name) {
        api.samlResponse.setAttribute(
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
            event.user.name
        );
    }

    // example of mapping a user metadata field
    // api.samlResponse.setAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/food', event.user.user_metadata.favorite_food);

    // an example of mapping an app metadata field
    // api.samlResponse.setAttribute('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/address', event.user.app_metadata.shipping_address);
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
