const { ManagementClient } = require('auth0');

const HTTP_TIMEOUT = 1000; // 1s

// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/add-persistence-attribute-PASSWORD_RESET_POST_CHALLENGE ---
/**
 * Handler that will be called during the execution of a Password Reset / Post Challenge Flow.
 *
 * @param {Event} event - Details about the post challenge request.
 * @param {PasswordResetPostChallengeAPI} api - Interface whose methods can be used to change the behavior of the post challenge flow.
 */
exports.onExecutePostChallenge = async (event, api) => {
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

    if (!event.secrets.CLIENT_ID) {
        return api.access.deny('missing client id');
    }

    const clientId = event.secrets.CLIENT_ID;

    if (!event.secrets.CLIENT_SECRET) {
        return api.access.deny('missing client secret');
    }

    const clientSecret = event.secrets.CLIENT_SECRET;

    if (!event.secrets.TENANT_DOMAIN) {
        return api.access.deny('missing tenant domain');
    }

    const domain = event.secrets.TENANT_DOMAIN;

    const management = new ManagementClient({
        domain,
        clientId,
        clientSecret,
        httpTimeout: HTTP_TIMEOUT,
    });

    await management.users.update(
        { id: event.user.user_id },
        {
            user_metadata: {
                [metadataKey]: metadataValue || metadataDefaultValue,
            },
        }
    );
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
