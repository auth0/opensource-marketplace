/**
 * @file Template for an Auth0 Action to handle a Custom Token Exchange.
 * This script implements the common scenario of validating an Auth0 access token,
 * received as a subject_token, and exchanging it for a new Auth0 access token with
 * a different audience. This enables first-party on-behalf-of flows for trusted services
 * calling downstream APIs.
 *
 * DISCLAIMER:
 * Custom Token Exchange gives you the added flexibility to set the user for the transaction
 * by taking on the additional responsibility of securely validating the corresponding
 * subject_token that identifies the user for the transaction.
 *
 * Remember that subject_tokens used with Custom Token Exchange can be any token format or
 * type you require, as long as your Action code can interpret them. You are responsible
 * for implementing strong validation of the tokens you receive and accept. Failing to do so
 * would make you liable for opening yourself up to different attack vectors, such as
 * spoofing or replay attacks, resulting in bad actors being able to authenticate with someone
 * else's user ID. https://auth0.com/docs/authenticate/custom-token-exchange#code-samples provides
 * best practices and examples for common scenarios for validating incoming subject tokens
 * in a secure and performant way.
 *
 * IMPORTANT: You must review and adapt this template to fit your specific configuration,
 * security, and application requirements. Access to modify this Action code must be strictly
 * controlled and limited to authorized personnel.
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
 * A first-party service (resource server, backend service, or Model Context Protocol server)
 * receives an Auth0 access token from a user. The service needs to call a downstream API on
 * behalf of that user. This Action validates the incoming token and issues a new token for
 * the downstream API while maintaining the same user identity (sub claim).
 *
 * EXAMPLE USE CASES:
 * - Resource servers calling backend APIs with user context
 * - Backend services performing on-behalf-of operations
 * - Model Context Protocol (MCP) servers accessing APIs for authenticated users
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
 * CONFIGURATION (4 required secrets):
 *
 * SUBJECT_TOKEN_AUDIENCE - Expected audience of incoming tokens (e.g., "https://api.example.com")
 * ALLOWED_CLIENT_IDS - JSON array of authorized client IDs (e.g., ["abc123"])
 * ALLOWED_TARGET_AUDIENCES - JSON array of permitted API identifiers (e.g., ["https://api.example.com"])
 * ALLOWED_SCOPES - JSON array of allowed scopes (e.g., ["openid", "read:data"])
 *
 * NOTE: subject_token_type is configured in the CTE profile and validated by the platform
 * before the Action is invoked. You do not need to validate it in your Action code.
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

// Validate organization-bound tokens are not used (CTE does not yet support Organizations)
const validateOrganization = (payload, api) => {
    if (payload.org_id) {
        return api.access.rejectInvalidSubjectToken(
            'Organization-bound token not eligible for exchange'
        );
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
        // Auth0 uses RS256 by default, with PS256 available on HRI SKU
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

    // Fast-fail if subject_token is missing
    if (!event.transaction?.subject_token) {
        return api.access.deny('invalid_request', 'subject_token is required');
    }

    try {
        const config = loadConfig(event.secrets);

        // NOTE: subject_token_type validation is handled upstream by the Custom Token Exchange
        // platform when matching the request to the configured CTE profile. The Action receives
        // requests only after the platform has verified the token type matches the profile.

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
            event.transaction.requested_scopes || [],
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

        // Validate organization-bound tokens are not used
        result = validateOrganization(payload, api);
        if (result) return result;

        // Validate token is not sender-constrained
        result = validateTokenConstraints(payload, api);
        if (result) return result;

        // Set user identity for new token (preserves original user)
        api.authentication.setUserById(payload.sub);
    } catch (err) {
        // Handle JSON configuration errors explicitly for easier debugging
        if (err instanceof SyntaxError && err.message.includes('JSON')) {
            logger.error(
                'Configuration JSON parse error in allow list secrets'
            );
            return api.access.deny('server_error', 'Token exchange failed');
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
