/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/add-minio-policy-open-id-claim-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // get the JWT Claim prefix for MinIO
    const jwtClaimPrefix = event.secrets.POST_LOGIN_MINIO_CLAIM_PREFIX;
    if (!jwtClaimPrefix) {
        return api.access.deny('Invalid configuration, missing POST_LOGIN_MINIO_CLAIM_PREFIX');
    }

    // get the fallback/default policy for un-mapped users
    const defaultPolicy = event.secrets.POST_LOGIN_MINIO_CLAIM_DEFAULT_POLICY;
    if (!defaultPolicy) {
        return api.access.deny('Invalid configuration, missing POST_LOGIN_MINIO_CLAIM_DEFAULT_POLICY');
    }

    // get the mapping of users to (pre-configured) MinIO policy names
    const userToPolicyMapJson = event.secrets.POST_LOGIN_MINIO_CLAIM_USER_POLICY_MAP;
    let userToPolicyMap;
    try {
        userToPolicyMap = JSON.parse(userToPolicyMapJson);
        if (typeof userToPolicyMap !== 'object' || Array.isArray(userToPolicyMap) || userToPolicyMap === null) {
            return api.access.deny('Mal-formatted userEmail-to-policyName mapping in POST_LOGIN_MINIO_CLAIM_USER_POLICY_MAP');
        }
    } catch (e) {
        console.error('Parsing POST_LOGIN_MINIO_CLAIM_USER_POLICY_MAP failed', e);
        return api.access.deny('Invalid configuration, POST_LOGIN_MINIO_CLAIM_USER_POLICY_MAP is invalid');
    }

    // reject login if the user's email is not available or verified
    if (!event.user.email || !event.user.email_verified) {
        return api.access.deny('Access denied, user email not available/verified');
    }

    // check if user email is in the mapping, if not, use the default policy
    const userMinioPolicy = userToPolicyMap[event.user.email.toLowerCase()] || defaultPolicy;

    // format the claim name, e.g. "https://minio.example.com/policy"
    const minioClaimName = jwtClaimPrefix.endsWith('/') ? `${jwtClaimPrefix}policy` : `${jwtClaimPrefix}/policy`;

    api.idToken.setCustomClaim(minioClaimName, userMinioPolicy);
    api.accessToken.setCustomClaim(minioClaimName, userMinioPolicy);

    // store the last assigned policy in the user's app_metadata property
    api.user.setAppMetadata('minioPolicyOpenIdClaim', `${minioClaimName}=${userMinioPolicy}`);
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
