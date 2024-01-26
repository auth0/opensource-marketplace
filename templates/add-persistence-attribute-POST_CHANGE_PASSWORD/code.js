const { ManagementClient } = require('auth0');

const HTTP_TIMEOUT = 1000; // 1s

// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/add-persistence-attribute-POST_CHANGE_PASSWORD ---
/**
 * Handler that will be called during the execution of a PostChangePassword flow.
 *
 * @param {Event} event - Details about the user and the context in which the change password is happening.
 * @param {PostChangePasswordAPI} api - Methods and utilities to help change the behavior after a user changes their password.
 */
exports.onExecutePostChangePassword = async (event, api) => {
    if (!event.secrets.METADATA_KEY) {
        console.log('missing event.secrets.METADATA_KEY');
        return;
    }

    const metadataKey = event.secrets.METADATA_KEY;

    if (!event.secrets.METADATA_DEFAULT_VALUE) {
        console.log('missing event.secrets.METADATA_DEFAULT_VALUE');
        return;
    }

    const metadataValue = event.user.user_metadata[metadataKey];

    // quit early if metadata is already set
    if (metadataValue) {
        return;
    }

    const metadataDefaultValue = event.secrets.METADATA_DEFAULT_VALUE;

    if (!event.secrets.CLIENT_ID) {
        console.log('missing event.secrets.CLIENT_ID');
        return;
    }

    const clientId = event.secrets.CLIENT_ID;

    if (!event.secrets.CLIENT_SECRET) {
        console.log('missing event.secrets.CLIENT_SECRET');
        return;
    }

    const clientSecret = event.secrets.CLIENT_SECRET;

    if (!event.secrets.TENANT_DOMAIN) {
        console.log('missing event.secrets.TENANT_DOMAIN');
        return;
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
