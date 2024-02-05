const { ManagementClient, AuthenticationClient } = require('auth0');

const HTTP_TIMEOUT = 1000; // 1s

// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/add-persistence-attribute-POST_USER_REGISTRATION ---
/**
 * Handler that will be called during the execution of a PostUserRegistration flow.. Makes use of a few SECRETS:
 * METADATA_KEY             - object key value to be set for the user
 * METADATA_DEFAULT_VALUE   - value to set for METADATA_KEY  on initialization
 * TENANT_DOMAIN            - Domain used for auth in AuthenticationClientOptions (See https://auth0.github.io/node-auth0/interfaces/auth.AuthenticationClientOptions.html for deetails on object)
 * CLIENT_ID                - Client ID used for auth in AuthenticationClientOptions
 * CLIENT_SECRET            - Client Secret used for auth in AuthenticationClientOptions
 * AUDIENCE                 - [OPTIONAL] Audience used
 *
 * @param {Event} event - Details about the context and user that has registered.
 * @param {PostUserRegistrationAPI} api - Methods and utilities to help change the behavior after a signup.
 */
exports.onExecutePostUserRegistration = async (event, api) => {
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

    if (!event.secrets.CLIENT_SECRET) {
        console.log('missing event.secrets.CLIENT_SECRET');
        return;
    }

    if (!event.secrets.TENANT_DOMAIN) {
        console.log('missing event.secrets.TENANT_DOMAIN');
        return;
    }

    const authenticationClientOptions = {
        domain: event.secrets.TENANT_DOMAIN,
        clientId: event.secrets.CLIENT_ID,
        clientSecret: event.secrets.CLIENT_SECRET,
        timeoutDuration: HTTP_TIMEOUT,
    };

    // if event.secrets.AUDIENCE is set, make use of the parameter for validating JWT is being used by intended Audience
    if (event.secrets.AUDIENCE) {
        authenticationClientOptions.audience = event.secrets.AUDIENCE;
    }

    const management = await getManagementApiClient(
        api.cache,
        authenticationClientOptions
    );

    await management.users.update(
        { id: event.user.user_id },
        {
            user_metadata: {
                [metadataKey]: metadataDefaultValue,
            },
        }
    );
};

/**
 * Get an AccessToken
 *
 * @param {CacheAPI} cache
 * @param {{domain: string, clientId: string, clientSecret: string, audience?: string, timeoutDuration: number}} options - AuthenticationClient options to fetch the token
 * @return {Promise<string>}
 */
async function getAccessToken(cache, options) {
    let key = `access_token_${options.clientId}`;

    if (options.audience) {
        key += `_${options.audience}`;
    }

    // Check the cache if we have a valid entry
    const record = cache.get(key);
    if (record && record.expires_at > Date.now()) {
        return record.value;
    }

    // Get the AccessToken using a client_credential grant.
    const authClient = new AuthenticationClient(options);

    const {
        data: { access_token, expires_in },
    } = await authClient.oauth.clientCredentialsGrant({
        audience: options.audience ?? `https://${options.domain}/api/v2/`,
    });

    // Try to cache it
    const cacheSetResult = cache.set(key, access_token, { ttl: expires_in });
    if (cacheSetResult.type === 'error') {
        console.error(`Failed to set ${key}: ${cacheSetResult.code}`);
    }

    return access_token;
}

/**
 * @param {CacheAPI} cache
 * @param {{domain: string, clientId: string, clientSecret: string, audience?: string, timeoutDuration: number}} options - AuthenticationClient options to fetch the token
 */
async function getManagementApiClient(cache, options) {
    const token = await getAccessToken(cache, options);

    return new ManagementClient({
        domain: options.domain,
        token,
        httpTimeout: HTTP_TIMEOUT,
    });
}
