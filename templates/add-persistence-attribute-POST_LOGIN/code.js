// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/add-persistence-attribute-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    if (!event.secrets.METADATA_KEY) {
        return api.access.deny('missing metadata key');
    }

    const metadataKey = event.secrets.METADATA_KEY;

    if (!event.secrets.METADATA_DEFAULT_VALUE) {
        return api.access.deny('missing metadata default value');
    }

    const metadataValue = event.user.user_metadata[metadataKey];

    // quit early if metadata is already set
    if (metadataValue) {
        return;
    }

    const metadataDefaultValue = event.secrets.METADATA_DEFAULT_VALUE;

    api.user.setUserMetadata(
        metadataKey,
        metadataValue || metadataDefaultValue
    );

    let namespace = event.secrets.ID_TOKEN_NAMESPACE || '';
    if (namespace && !namespace.endsWith('/')) {
        namespace += '/';
    }

    api.idToken.setCustomClaim(
        namespace + metadataKey,
        metadataValue || metadataDefaultValue
    );
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
