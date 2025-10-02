/**
 * Handler that will be called during the execution of a Custom Token Exchange flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/first-party-custom-token-exchange-CUSTOM_TOKEN_EXCHANGE ---
 *
 * Implements RFC 8693 OAuth 2.0 Token Exchange for first-party on-behalf-of flows.
 * Exchanges Auth0 access tokens for different API audiences while preserving user identity.
 *
 * DOCUMENTATION:
 * - RFC 8693: https://datatracker.ietf.org/doc/html/rfc8693
 * - Auth0 Custom Token Exchange: https://auth0.com/docs/authenticate/custom-token-exchange
 * - Actions Limitations: https://auth0.com/docs/customize/actions/limitations
 *
 * COMMON SCENARIO:
 * Your Model Context Protocol (MCP) server receives a token from a user. The server needs
 * to call your backend API on behalf of that user. This Action validates the incoming token
 * and issues a new token for the backend API while maintaining the same user identity (sub claim).
 *
 * WHY THIS PATTERN:
 * - Security: Each API gets tokens specifically scoped for its audience
 * - Least Privilege: Control exactly which scopes are granted to downstream services
 * - Auditability: Preserve user identity across the entire request chain
 * - Best Practice: Follows RFC 8693 standard for delegated authorization
 *
 * UNDERSTANDING SCOPE DECOUPLING:
 * The scopes on the incoming subject token do NOT map 1:1 to the scopes on the exchanged token.
 * The subject token's scopes authorize the user's request TO THIS SERVICE, while the exchanged
 * token's scopes authorize THIS SERVICE's request to a downstream API on the user's behalf.
 * These are separate authorization contexts and typically use different scope vocabularies.
 *
 * CONFIGURATION (5 required secrets):
 *
 * SUBJECT_TOKEN_TYPE - The CTE profile identifier (e.g., "urn:mycompany:mcp-token")
 * SUBJECT_TOKEN_AUDIENCE - Expected audience of incoming tokens (e.g., "https://mcp.example.com")
 * ALLOWED_CLIENT_IDS - JSON array of authorized client IDs (e.g., ["abc123"])
 * ALLOWED_TARGET_AUDIENCES - JSON array of permitted API identifiers (e.g., ["https://api.example.com"])
 * ALLOWED_SCOPES - JSON array of allowed scopes (e.g., ["openid", "read:data"])
 *
 * OPTIONAL:
 *
 * DEBUG - Enable debug logging (e.g., "token-exchange:*" for all, "token-exchange:error" for errors only)
 *
 * @param {Event} event - Details about the token exchange request
 * @param {CustomTokenExchangeAPI} api - Interface to control the exchange flow
 */

const { jwtVerify, createRemoteJWKSet } = require('jose');
const debug = require('debug');

// Always enable error logging, allow DEBUG secret to enable more verbose logging
debug.enable('token-exchange:error');

const logger = {
    error: debug('token-exchange:error'),
    info: debug('token-exchange:info'),
};

// Cache for JWKS clients (persists across warm container invocations)
const jwksCache = new Map();

// jose error code to user-friendly message mapping
const JOSE_ERROR_MESSAGES = {
    ERR_JWT_EXPIRED: 'The subject token has expired',
    ERR_JWS_SIGNATURE_VERIFICATION_FAILED:
        'Token signature verification failed',
    ERR_JWT_CLAIM_VALIDATION_FAILED: 'Token claim validation failed',
    ERR_JWKS_NO_MATCHING_KEY: 'No matching signing key found for token',
    ERR_JWKS_MULTIPLE_MATCHING_KEYS: 'Multiple matching signing keys found',
    ERR_JWT_INVALID: 'The subject token is invalid',
};

// Parse and validate JSON array secret
const parseArraySecret = (value, name) => {
    const trimmed = value?.trim();
    if (!trimmed) {
        throw new Error(`Secret '${name}' is required`);
    }

    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed) || parsed.length === 0) {
        throw new Error(`Secret '${name}' must be a non-empty JSON array`);
    }

    return parsed;
};

// Validate required string secret
const requireSecret = (value, name) => {
    const trimmed = value?.trim();
    if (!trimmed) {
        throw new Error(`Secret '${name}' is required`);
    }
    return trimmed;
};

// Load and validate configuration from secrets
const loadConfig = (secrets) => ({
    subjectTokenType: requireSecret(
        secrets.SUBJECT_TOKEN_TYPE,
        'SUBJECT_TOKEN_TYPE'
    ),
    subjectTokenAudience: requireSecret(
        secrets.SUBJECT_TOKEN_AUDIENCE,
        'SUBJECT_TOKEN_AUDIENCE'
    ),
    allowedClients: new Set(
        parseArraySecret(secrets.ALLOWED_CLIENT_IDS, 'ALLOWED_CLIENT_IDS')
    ),
    allowedAudiences: new Set(
        parseArraySecret(
            secrets.ALLOWED_TARGET_AUDIENCES,
            'ALLOWED_TARGET_AUDIENCES'
        )
    ),
    allowedScopes: new Set(
        parseArraySecret(secrets.ALLOWED_SCOPES, 'ALLOWED_SCOPES')
    ),
});

// Validate subject token type matches profile
const validateTokenType = (actual, expected, api) => {
    if (actual !== expected) {
        return api.access.deny(
            'invalid_request',
            `subject_token_type must be '${expected}'`
        );
    }
};

// Validate client is authorized
const validateClient = (clientId, clientName, allowedClients, api) => {
    if (!allowedClients.has(clientId)) {
        logger.error('Unauthorized client attempted exchange', {
            clientId,
            clientName,
        });
        return api.access.deny(
            'unauthorized_client',
            'This client is not authorized to perform token exchange'
        );
    }
};

// Validate target audience is permitted
const validateAudience = (audience, allowedAudiences, api) => {
    if (!audience) {
        return api.access.deny(
            'invalid_request',
            'No target audience specified'
        );
    }

    if (!allowedAudiences.has(audience)) {
        logger.error('Unauthorized audience requested', { audience });
        return api.access.deny(
            'invalid_target',
            'The requested audience is not permitted'
        );
    }
};

// Normalize requested scopes to array (RFC 8693 allows space-delimited string or array)
const normalizeScopes = (scopes) => {
    if (Array.isArray(scopes)) {
        return scopes;
    }
    return (scopes || '').trim().split(/\s+/).filter(Boolean);
};

// Validate requested scopes are allowed
// NOTE: This validates against a flat list of allowed scopes. Ideally we would
// validate scopes per resource server (audience), but the Actions API does not
// currently provide access to the resource server -> scope configuration.
const validateScopes = (requestedScopes, allowedScopes, api) => {
    const unauthorized = requestedScopes.filter((s) => !allowedScopes.has(s));

    if (unauthorized.length > 0) {
        logger.error('Unauthorized scopes requested', { unauthorized });
        return api.access.deny(
            'invalid_scope',
            `Unauthorized scopes requested: ${unauthorized.join(', ')}`
        );
    }
};

// Validate the token was issued to the client presenting it
const validateTokenBinding = (payload, clientId, api) => {
    const tokenClientId = payload.azp || payload.client_id;
    if (tokenClientId && tokenClientId !== clientId) {
        return api.access.rejectInvalidSubjectToken(
            'The subject token was not issued to the calling client.'
        );
    }
};

// Validate organization binding when Organizations are in use
const validateOrganization = (payload, organization, api) => {
    if (organization && payload.org_id && payload.org_id !== organization.id) {
        return api.access.rejectInvalidSubjectToken('Organization mismatch');
    }
};

// Validate token is not sender-constrained (DPoP, mTLS)
const validateTokenConstraints = (payload, api) => {
    if (payload.cnf) {
        return api.access.rejectInvalidSubjectToken(
            'Sender-constrained token not eligible for exchange'
        );
    }
};

// Get Auth0 issuer URL for the current tenant
const getAuth0Issuer = (event) => {
    return new URL(`https://${event.request.hostname}/`);
};

// Get or create JWKS client for issuer
const getJWKSClient = (issuer) => {
    const issuerText = issuer.toString();
    let client = jwksCache.get(issuerText);
    if (!client) {
        // Actions have a 20 second execution limit (see https://auth0.com/docs/customize/actions/limitations)
        // Set cooldown to 15s to ensure JWKS refresh completes within the timeout
        client = createRemoteJWKSet(new URL('.well-known/jwks.json', issuer), {
            timeoutDuration: 5000,
            cooldownDuration: 15000,
        });
        jwksCache.set(issuerText, client);
        logger.info(`Initialized JWKS client for ${issuerText}`);
    }
    return client;
};

// Verify incoming Auth0 access token
const verifyToken = async (token, issuer, audience) => {
    const { payload } = await jwtVerify(token, getJWKSClient(issuer), {
        issuer: issuer.toString(),
        audience,
        // Restrict to commonly-used signing algorithms to reduce attack surface
        // Verify your tenant's algorithm by checking /.well-known/openid-configuration
        // and adjust this list if needed (e.g., add 'ES256' if your tenant uses it)
        algorithms: ['RS256', 'PS256'],
        clockTolerance: 5,
    });

    if (!payload.sub || typeof payload.sub !== 'string') {
        throw new Error('Token missing valid subject claim');
    }

    return payload;
};

/**
 * Handles the Custom Token Exchange request.
 * @param {Event} event - Details about the incoming token exchange request.
 * @param {CustomTokenExchangeAPI} api - Methods and utilities to define the token exchange process.
 */
exports.onExecuteCustomTokenExchange = async (event, api) => {
    // Add additional debug namespaces if DEBUG secret is configured
    if (event.secrets.DEBUG) {
        debug.enable('token-exchange:error,' + event.secrets.DEBUG);
    }

    try {
        const config = loadConfig(event.secrets);

        // Validate subject token type matches profile
        let result = validateTokenType(
            event.transaction.subject_token_type,
            config.subjectTokenType,
            api
        );
        if (result) return result;

        // Validate client is authorized
        result = validateClient(
            event.client.client_id,
            event.client.name,
            config.allowedClients,
            api
        );
        if (result) return result;

        // Validate target audience is permitted
        result = validateAudience(
            event.resource_server?.identifier,
            config.allowedAudiences,
            api
        );
        if (result) return result;

        // Validate requested scopes are allowed
        result = validateScopes(
            normalizeScopes(event.transaction.requested_scopes),
            config.allowedScopes,
            api
        );
        if (result) return result;

        // Cryptographically verify incoming Auth0 access token
        const issuer = getAuth0Issuer(event);
        const payload = await verifyToken(
            event.transaction.subject_token,
            issuer,
            config.subjectTokenAudience
        );

        // Validate token was issued to the calling client
        result = validateTokenBinding(payload, event.client.client_id, api);
        if (result) return result;

        // Validate organization binding
        result = validateOrganization(payload, event.organization, api);
        if (result) return result;

        // Validate token is not sender-constrained
        result = validateTokenConstraints(payload, api);
        if (result) return result;

        // Set user identity for new token (preserves original user)
        api.authentication.setUserById(payload.sub);
    } catch (err) {
        // Handle JSON configuration errors explicitly for easier debugging
        if (err instanceof SyntaxError && err.message.includes('JSON')) {
            const errorMessage =
                'Configuration error: One of the ALLOWED_* secrets contains invalid JSON.';
            logger.error(errorMessage);
            return api.access.deny('server_error', errorMessage);
        }

        logger.error(`Token exchange failed: ${err.code || err.name}`);

        // Handle known jose library errors - use rejectInvalidSubjectToken
        // for attack protection (enables Suspicious IP Throttling)
        const joseErrorMessage = JOSE_ERROR_MESSAGES[err.code];
        if (joseErrorMessage) {
            const message =
                err.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED' && err.claim
                    ? `Token claim '${err.claim}' validation failed`
                    : joseErrorMessage;

            return api.access.rejectInvalidSubjectToken(message);
        }

        // All other errors (configuration, network, unknown) - fail closed
        return api.access.deny('server_error', 'Token exchange failed');
    }
};
