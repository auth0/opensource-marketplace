const { jwtVerify, createRemoteJWKSet } = require('jose');
var validator = require('validator');

// Action Config (dependent on client setup)
const DB_NAME = '{{YOUR_CONNECTION_NAME}}'; // Auth0 DB connection

// Skyfire verification details
const JWKS_URL = 'https://app.skyfire.xyz/.well-known/jwks.json'; // Skyfire jwks url
const JWT_ISSUER = 'https://app.skyfire.xyz'; // skyfire domain

/**
 * Handler to be executed while executing a custom token exchange request
 * @param {Event} event - Details about the incoming token exchange request.
 * @param {CustomTokenExchangeAPI} api - Methods and utilities to define token exchange process.
 */
exports.onExecuteCustomTokenExchange = async (event, api) => {
    const subject_token = event.transaction.subject_token; // Skyfire token

    // Token validation starts
    const JWKS = createRemoteJWKSet(new URL(JWKS_URL));

    let decodedPayload = null;

    try {
        const { payload, protectedHeader } = await jwtVerify(
            subject_token,
            JWKS,
            {
                issuer: JWT_ISSUER,
                algorithms: ['ES256'],
            }
        );

        if (!['kya+JWT', 'kya+pay+JWT'].includes(protectedHeader.typ)) {
            console.log('Invalid typ:', protectedHeader.typ);
            return api.access.deny(
                'invalid_typ',
                'typ should be one of kya+JWT or kya+pay+JWT'
            );
        }

        decodedPayload = payload;
    } catch (err) {
        console.log('JWT verification failed:', err.message || err);
        return api.access.deny(
            'invalid_token',
            'JWT verification failed: invalid token.'
        );
    }

    // JWT successfully verified, now verify skyfireEmail
    const isEmailValid = validator.isEmail(decodedPayload.bid.skyfireEmail);

    if (!isEmailValid) {
        console.log('Invalid email format');
        return api.access.deny('invalid_email', 'Invalid email format.');
    }

    // Validate env is 'production'
    if (decodedPayload.env !== 'production') {
        console.log('Invalid environment:', decodedPayload.env);
        return api.access.deny(
            'invalid_env',
            'Token is not from production environment.'
        );
    }

    const now = Math.floor(Date.now() / 1000); // current time in seconds

    // Validate iat is in the past
    if (typeof decodedPayload.iat !== 'number' || decodedPayload.iat > now) {
        console.log('Invalid iat:', decodedPayload.iat);
        return api.access.deny(
            'invalid_iat',
            'Issued-at time is in the future or missing.'
        );
    }

    // Validate exp is now or in the future
    if (typeof decodedPayload.exp !== 'number' || decodedPayload.exp <= now) {
        console.log('Token has expired:', decodedPayload.exp);
        return api.access.deny('token_expired', 'Token has expired.');
    }

    // Validate jti is a UUID
    if (!validator.isUUID(decodedPayload.jti)) {
        console.log('Invalid jti:', decodedPayload.jti);
        return api.access.deny(
            'invalid_jti',
            'Invalid token ID (jti): not a valid UUID.'
        );
    }

    // Validate sub is a UUID
    if (!validator.isUUID(decodedPayload.sub)) {
        console.log('Invalid sub:', decodedPayload.sub);
        return api.access.deny(
            'invalid_sub',
            'Invalid subject (sub): not a valid UUID.'
        );
    }

    // Validate aud is a UUID
    if (!validator.isUUID(decodedPayload.aud)) {
        console.log('Invalid aud:', decodedPayload.aud);
        return api.access.deny(
            'invalid_aud',
            'Invalid audience (aud): not a valid UUID.'
        );
    }

    // Token validation ends

    // Mapping Skyfire token to Auth0 user
    api.authentication.setUserByConnection(
        DB_NAME, // Auth0 DB connection
        {
            user_id: decodedPayload.sub,
            email: decodedPayload.bid.skyfireEmail,
            email_verified: true,
            given_name: decodedPayload.bid.nameFirst,
            family_name: decodedPayload.bid.nameLast,
            username: decodedPayload.bid.skyfireEmail,
            name:
                decodedPayload.bid.nameFirst +
                ' ' +
                decodedPayload.bid.nameLast,
            nickname: decodedPayload.bid.nameFirst,
            verify_email: false,
        },
        {
            creationBehavior: 'create_if_not_exists',
            updateBehavior: 'none',
        }
    );
};
