/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/saml-configuration-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    if (!event.secrets.CLIENT_ID) {
        return api.access.deny('Invalid configuration');
    }

    if (!event.secrets.SAML_AUD) {
        return api.access.deny('Invalid configuration');
    }

    if (!event.secrets.SAML_RECIPIENT) {
        return api.access.deny('Invalid configuration');
    }

    if (!event.secrets.SAML_DESTINATION) {
        return api.access.deny('Invalid configuration');
    }

    if (!event.secrets.SAML_LIFETIME_SEC) {
        return api.access.deny('Invalid configuration');
    }

    if (event.client.client_id === event.secrets.CLIENT_ID) {
        api.samlResponse.setAudience(event.secrets.SAML_AUD);
        api.samlResponse.setRecipient(event.secrets.SAML_RECIPIENT);
        api.samlResponse.setDestination(event.secrets.SAML_DESTINATION);
        api.samlResponse.setLifetimeInSeconds(
            Number(event.secrets.SAML_LIFETIME_SEC)
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
