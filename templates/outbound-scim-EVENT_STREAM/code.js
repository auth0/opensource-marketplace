/**
 * outbound-scim-EVENT_STREAM v0.6.0
 *
 * Auth0 Action template for outbound SCIM 2.0 user provisioning:
 *   user.created -> POST /Users
 *   user.updated -> find by externalId, then PUT /Users/{id}
 *   user.deleted -> find by externalId, then DELETE /Users/{id}
 * Correlation is by SCIM externalId (= Auth0 user_id), falling back to a
 * userName search when a destination rejects externalId filtering.
 *
 * Setup and how it works:
 * https://auth0.com/docs/customize/events/send-outbound-scim
 *
 * BEFORE YOU SAVE: add these Action Secrets (Secrets panel, key icon).
 *   REQUIRED
 *     SCIM_BASE_URL              SCIM 2.0 base URL, e.g. https://api.example.com/scim/v2
 *     SCIM_BEARER_TOKEN          Bearer token for your SCIM server
 *   OPTIONAL
 *     SCIM_TIMEOUT_MS            Per-request timeout, ms (default 1500)
 *     SCIM_MAX_RETRIES           Retries on 429 / 5xx / network (default 1)
 *     SCIM_CONNECTION_ALLOWLIST  CSV of connection names to process (default: all)
 *
 * Edit buildScimUser() below to map your Auth0 profile to the destination schema.
 *
 * @typedef {import('@auth0/actions/event-stream/v1').Event} Event
 * @typedef {import('@auth0/actions/event-stream/v1').EventStreamAPI} EventStreamAPI
 *
 * The template reads these secrets from the Event Stream payload; see readConfig().
 * @typedef {Object} Secrets
 * @property {string | undefined} SCIM_BASE_URL
 * @property {string | undefined} SCIM_BEARER_TOKEN
 * @property {string | undefined} SCIM_TIMEOUT_MS
 * @property {string | undefined} SCIM_MAX_RETRIES
 * @property {string | undefined} SCIM_CONNECTION_ALLOWLIST
 *
 * The editor's ambient fetch/Response type omits `status`, so we describe the
 * response slice this template reads. `json()` returns `Promise<unknown>`, so
 * each parsed body must be validated through the parseScim* helpers below
 * before the template reads a field.
 * @typedef {Object} ScimResponse
 * @property {number} status
 * @property {() => Promise<unknown>} json
 *
 * Correlation slice of a SCIM User resource, validated out of a response body.
 * `id` is the only field the template requires (it builds the PUT/DELETE path
 * from it); `externalId` is optional and gates conflict dedup.
 * @typedef {Object} ScimUser
 * @property {string} id
 * @property {string} [externalId]
 *
 * Error carrying the SCIM diagnostic fields set in scimError().
 * @typedef {Error & { status?: number, scimType?: string, detail?: string, cause?: any }} ScimError
 *
 * Resolved configuration produced by readConfig().
 * @typedef {Object} Config
 * @property {string} [scimBaseUrl]
 * @property {string} [scimBearerToken]
 * @property {number} scimTimeoutMs
 * @property {number} scimMaxRetries
 * @property {string[]} connectionAllowlist
 *
 * The Auth0 user profile slice this template maps to SCIM. The runtime object
 * carries more fields; only the ones buildScimUser() reads are declared.
 * @typedef {Object} Auth0User
 * @property {string} [user_id]
 * @property {boolean} [blocked]
 * @property {string} [email]
 * @property {string} [given_name]
 * @property {string} [family_name]
 * @property {string} [name]
 * @property {string} [nickname]
 * @property {Record<string, any>} [user_metadata]
 *
 * The event payload slice the template reads after unwrapEventPayload(). The
 * runtime shape is looser than the published `Event` type (e.g. `a0purpose` is
 * only present on simulator calls), so this describes what the code consumes.
 * @typedef {Object} UserEvent
 * @property {string} [type]
 * @property {string} [id]
 * @property {string} [a0purpose]
 * @property {{ object: Auth0User, context?: { connection?: { name?: string } } }} data
 *
 * The mutable SCIM User resource buildScimUser() assembles for the request body.
 * @typedef {Object} ScimUserPayload
 * @property {string[]} schemas
 * @property {string} [externalId]
 * @property {boolean} active
 * @property {string} [userName]
 * @property {Array<{ value: string, type: string, primary: boolean }>} [emails]
 * @property {{ givenName?: string, familyName?: string, formatted?: string }} [name]
 * @property {string} [displayName]
 * @property {string} [nickName]
 * @property {Array<{ value: string, type: string, primary: boolean }>} [phoneNumbers]
 *
 * @param {Event} event
 * @param {EventStreamAPI} api
 */
exports.onExecuteEventStream = async (event, api) => {
    const config = readConfig(event.secrets);
    if (!validateRequiredSecrets(config)) return;

    const userEvent = unwrapEventPayload(event);
    if (!userEvent) return;

    const auth0User = userEvent.data.object;
    const logCtx = {
        type: userEvent.type,
        eventId: userEvent.id,
        userId: auth0User.user_id,
    };

    if (isSimulatorCall(userEvent)) {
        log('info', 'Simulator call detected; skipping SCIM sync', logCtx);
        return;
    }

    if (!isAllowedConnection(userEvent, config)) {
        log('info', 'Connection not in allowlist; skipping', {
            ...logCtx,
            connection: userEvent.data?.context?.connection?.name,
        });
        return;
    }

    try {
        const result = await dispatchByEventType(userEvent, config);
        if (result) log('info', 'SCIM sync ok', { ...logCtx, ...result });
    } catch (err) {
        log('error', 'SCIM sync failed', {
            ...logCtx,
            ...errorLogFields(/** @type {ScimError} */ (err)),
        });
        // Throw so Event Streams retries / DLQs the delivery; returning would
        // mark it delivered and silently drop the event. Retry & failure model:
        // https://auth0.com/docs/customize/events/event-testing-observability-and-failure-recovery
        throw err;
    }
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const EVENT_TYPE = {
    USER_CREATED: 'user.created',
    USER_UPDATED: 'user.updated',
    USER_DELETED: 'user.deleted',
};

const HTTP = {
    OK: 200,
    CREATED: 201,
    NO_CONTENT: 204,
    BAD_REQUEST: 400,
    NOT_FOUND: 404,
    CONFLICT: 409,
    TOO_MANY_REQUESTS: 429,
    SERVER_ERROR_THRESHOLD: 500,
};

const SCIM_SCHEMA = {
    CORE_USER: 'urn:ietf:params:scim:schemas:core:2.0:User',
    ENTERPRISE_USER:
        'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User',
};

// SCIM 2.0 protocol (RFC 7644). Cited in shape errors so an operator seeing the
// log knows what the destination should return (§3.3 User, §3.4.2 ListResponse).
const SCIM_SPEC_URL = 'https://datatracker.ietf.org/doc/html/rfc7644';

const SIMULATOR_MARKER = 'test';

// Sized so a worst-case delivery (multiple SCIM requests + retries/backoff)
// stays within the Event Stream execution budget. If a destination needs
// externalId-filter fallback and you see timeouts, lower SCIM_TIMEOUT_MS;
// raising these defaults risks exceeding the budget. Execution limits:
// https://auth0.com/docs/customize/actions/limitations#executions
const DEFAULTS = {
    REQUEST_TIMEOUT_MS: 1500,
    MAX_RETRIES: 1,
    RETRY_BASE_DELAY_MS: 250,
    RETRY_MAX_DELAY_MS: 1000,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * @param {Partial<Secrets>} [secrets]
 * @returns {Config}
 */
function readConfig(secrets = {}) {
    return {
        scimBaseUrl: trimTrailingSlash(secrets.SCIM_BASE_URL),
        scimBearerToken: secrets.SCIM_BEARER_TOKEN,
        scimTimeoutMs: parseInteger(
            secrets.SCIM_TIMEOUT_MS,
            DEFAULTS.REQUEST_TIMEOUT_MS,
            1
        ),
        scimMaxRetries: parseInteger(
            secrets.SCIM_MAX_RETRIES,
            DEFAULTS.MAX_RETRIES,
            0
        ),
        connectionAllowlist: parseCsv(secrets.SCIM_CONNECTION_ALLOWLIST),
    };
}

/**
 * @param {Config} config
 * @returns {boolean}
 */
function validateRequiredSecrets(config) {
    if (!config.scimBaseUrl) {
        log('error', 'Missing required Action secret', {
            secret: 'SCIM_BASE_URL',
        });
        return false;
    }
    if (!config.scimBearerToken) {
        log('error', 'Missing required Action secret', {
            secret: 'SCIM_BEARER_TOKEN',
        });
        return false;
    }
    return true;
}

/**
 * @param {string | undefined} value
 * @returns {string[]}
 */
function parseCsv(value) {
    if (!value) return [];
    return String(value)
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
}

/**
 * @param {string | number | undefined} value
 * @param {number} defaultValue
 * @param {number} minimum
 * @returns {number}
 */
function parseInteger(value, defaultValue, minimum) {
    const parsed = Number(value);
    return Number.isInteger(parsed) && parsed >= minimum
        ? parsed
        : defaultValue;
}

/**
 * @param {string | undefined} url
 * @returns {string | undefined}
 */
function trimTrailingSlash(url) {
    return url ? String(url).replace(/\/+$/, '') : url;
}

// ---------------------------------------------------------------------------
// Event processing
// ---------------------------------------------------------------------------

/**
 * @param {Event} event
 * @returns {UserEvent | null}
 */
function unwrapEventPayload(event) {
    // The published CloudEvent `message` shape and the runtime payload this
    // template reads (data.object, a0purpose, context.connection) don't overlap
    // enough for a direct cast, so reinterpret via `unknown` - the parseScim*
    // / hasCorrelationKey guards below validate the fields before any write.
    const userEvent = /** @type {UserEvent} */ (
        /** @type {unknown} */ (event.message ?? event)
    );
    if (!userEvent?.type || !userEvent?.data?.object) {
        log('warn', 'Skipping malformed event', {
            keys: Object.keys(userEvent ?? {}),
        });
        return null;
    }
    return userEvent;
}

/**
 * Auth0 sets `a0purpose: 'test'` only on Event Stream simulator events. Skip
 * them so clicking "test" never provisions a fake user. Intentional - keep it.
 *
 * @param {UserEvent} userEvent
 * @returns {boolean}
 */
function isSimulatorCall(userEvent) {
    return userEvent.a0purpose === SIMULATOR_MARKER;
}

/**
 * @param {UserEvent} userEvent
 * @param {Config} config
 * @returns {boolean}
 */
function isAllowedConnection(userEvent, config) {
    if (config.connectionAllowlist.length === 0) return true;
    const connectionName = userEvent.data?.context?.connection?.name;
    return (
        !!connectionName && config.connectionAllowlist.includes(connectionName)
    );
}

// ---------------------------------------------------------------------------
// Lifecycle handlers
// ---------------------------------------------------------------------------

/**
 * @param {UserEvent} userEvent
 * @param {Config} config
 * @returns {Promise<Record<string, unknown> | null>}
 */
async function dispatchByEventType(userEvent, config) {
    switch (userEvent.type) {
        case EVENT_TYPE.USER_CREATED:
            return onUserCreated(userEvent, config);
        case EVENT_TYPE.USER_UPDATED:
            return onUserUpdated(userEvent, config);
        case EVENT_TYPE.USER_DELETED:
            return onUserDeleted(userEvent, config);
        default:
            log('info', 'Ignoring unsupported event type', {
                type: userEvent.type,
                eventId: userEvent.id,
            });
            return null;
    }
}

/**
 * @param {UserEvent} userEvent
 * @param {Config} config
 * @returns {Promise<Record<string, unknown>>}
 */
async function onUserCreated(userEvent, config) {
    const auth0User = userEvent.data.object;
    const scimUser = buildScimUser(auth0User);

    // externalId (= Auth0 user_id) is the correlation key. Without it a later
    // 409 cannot be told apart from a true duplicate, so skip before any write.
    if (!hasCorrelationKey(scimUser)) {
        log('warn', 'Skipping create: externalId (Auth0 user_id) is missing', {
            eventId: userEvent.id,
        });
        return { skipped: 'missing externalId' };
    }

    if (!hasRequiredIdentity(scimUser)) {
        log('warn', 'Skipping create: SCIM userName is missing', {
            userId: auth0User.user_id,
            eventId: userEvent.id,
        });
        return { skipped: 'missing userName' };
    }

    return createRemoteUser(config, scimUser, 'created');
}

/**
 * @param {UserEvent} userEvent
 * @param {Config} config
 * @returns {Promise<Record<string, unknown>>}
 */
async function onUserUpdated(userEvent, config) {
    const auth0User = userEvent.data.object;
    const scimUser = buildScimUser(auth0User);

    // No externalId means findUser falls back to userName, which could PUT over
    // a different person sharing the email. Skip before any lookup or write.
    if (!hasCorrelationKey(scimUser)) {
        log('warn', 'Skipping update: externalId (Auth0 user_id) is missing', {
            eventId: userEvent.id,
        });
        return { skipped: 'missing externalId' };
    }

    if (!hasRequiredIdentity(scimUser)) {
        log('warn', 'Skipping update: SCIM userName is missing', {
            userId: auth0User.user_id,
            eventId: userEvent.id,
        });
        return { skipped: 'missing userName' };
    }

    const remote = await findUser(config, scimUser);

    // No matching SCIM user: skip by default, since silently creating one can
    // mask a missed user.created. OPTIONAL UPSERT (create-on-update): replace
    // the log + return below with `return createRemoteUser(config, scimUser,
    // 'created-from-update');` if your destination can legitimately miss creates.
    if (!remote) {
        log(
            'warn',
            'Skipping update: no matching SCIM user (UPSERT disabled)',
            {
                userId: auth0User.user_id,
                eventId: userEvent.id,
            }
        );
        return { skipped: 'no SCIM user to update' };
    }

    // Verb + body in variables so the request and its error label stay in sync.
    // OPTIONAL: some targets (e.g. Microsoft Entra ID) accept only PATCH, not
    // PUT. To switch, set these to method 'PATCH' and a PatchOp body, e.g.:
    //   const updateMethod = 'PATCH';
    //   const updateBody = {
    //       schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
    //       Operations: [{ op: 'replace', value: scimUser }],
    //   };
    // Confirm your server supports path-less replace; otherwise send one op per
    // attribute. Nothing else needs to change - the request reads updateMethod.
    const updateMethod = 'PUT';
    const updateBody = scimUser;

    const res = await request(
        config,
        updateMethod,
        userPath(remote.id),
        updateBody
    );
    if (res.status === HTTP.OK || res.status === HTTP.NO_CONTENT) {
        return { scimId: remote.id, action: 'updated' };
    }

    throw await scimError(`${updateMethod} ${userPath(remote.id)}`, res);
}

/**
 * @param {UserEvent} userEvent
 * @param {Config} config
 * @returns {Promise<Record<string, unknown>>}
 */
async function onUserDeleted(userEvent, config) {
    const auth0User = userEvent.data.object;
    const scimUser = buildScimUser(auth0User);

    // No externalId means findUser falls back to userName, which could DELETE a
    // different person sharing the email. Skip before any lookup or write.
    if (!hasCorrelationKey(scimUser)) {
        log('warn', 'Skipping delete: externalId (Auth0 user_id) is missing', {
            eventId: userEvent.id,
        });
        return { skipped: 'missing externalId' };
    }

    const remote = await findUser(config, scimUser);

    if (!remote) return { skipped: 'no SCIM user to delete' };

    const path = userPath(remote.id);
    const res = await request(config, 'DELETE', path);
    if (res.status === HTTP.OK || res.status === HTTP.NO_CONTENT) {
        return { scimId: remote.id, action: 'deleted' };
    }
    if (res.status === HTTP.NOT_FOUND) {
        return { scimId: remote.id, skipped: 'already gone' };
    }

    throw await scimError(`DELETE ${path}`, res);
}

/**
 * @param {Config} config
 * @param {ScimUserPayload} scimUser
 * @param {string} action
 * @returns {Promise<Record<string, unknown>>}
 */
async function createRemoteUser(config, scimUser, action) {
    const res = await request(config, 'POST', '/Users', scimUser);
    if (res.status === HTTP.CREATED) {
        // A 201 with no usable id can't be returned as a real scimId; throw so
        // the delivery retries / DLQs instead of reporting a bogus success.
        const created = parseScimUser(await readJsonSafely(res));
        if (!created)
            throw scimShapeError(
                'POST /Users',
                res,
                'a User resource with a string "id" (RFC 7644 §3.3)'
            );
        return { scimId: created.id, action };
    }

    // A 409 is ambiguous: duplicate delivery vs. a real conflict on someone
    // else's userName/email. Treat as success ONLY when a follow-up lookup
    // confirms the same externalId we sent; anything else throws (retry/DLQ).
    // The `scimUser.externalId &&` guard is load-bearing - without it an
    // externalId-less match would `undefined === undefined` and hide a real conflict.
    if (res.status === HTTP.CONFLICT) {
        const conflict = await scimError('POST /Users', res);
        let remote;
        try {
            remote = await findUser(config, scimUser);
        } catch (lookupErr) {
            // Reconcile lookup failed: surface the original 409, keep the lookup
            // error as `cause` for observability rather than masking the conflict.
            conflict.cause = lookupErr;
            throw conflict;
        }
        if (
            remote &&
            scimUser.externalId &&
            remote.externalId === scimUser.externalId
        ) {
            return {
                scimId: remote.id,
                skipped: 'duplicate delivery (externalId match)',
            };
        }
        throw conflict;
    }

    throw await scimError('POST /Users', res);
}

// ---------------------------------------------------------------------------
// SCIM payload builder
// ---------------------------------------------------------------------------

/**
 * Customer edit point: map the Auth0 user profile to a SCIM User resource.
 *
 * @param {Auth0User} auth0User
 * @returns {ScimUserPayload}
 */
function buildScimUser(auth0User) {
    /** @type {ScimUserPayload} */
    const scimUser = {
        schemas: [SCIM_SCHEMA.CORE_USER],
        externalId: auth0User.user_id,
        active: auth0User.blocked !== true,
    };

    if (auth0User.email) {
        scimUser.userName = auth0User.email;
        scimUser.emails = [
            { value: auth0User.email, type: 'work', primary: true },
        ];
    }

    /** @type {{ givenName?: string, familyName?: string, formatted?: string }} */
    const name = {};
    if (auth0User.given_name) name.givenName = auth0User.given_name;
    if (auth0User.family_name) name.familyName = auth0User.family_name;
    if (auth0User.name) {
        name.formatted = auth0User.name;
        scimUser.displayName = auth0User.name;
    }
    if (Object.keys(name).length > 0) scimUser.name = name;

    if (auth0User.nickname) scimUser.nickName = auth0User.nickname;

    const metadata = auth0User.user_metadata ?? {};
    if (metadata.phone) {
        scimUser.phoneNumbers = [
            { value: metadata.phone, type: 'work', primary: true },
        ];
    }

    // OPTIONAL SCIM Enterprise User extension. Uncomment and adjust the metadata
    // paths for your tenant / destination schema.
    //
    // const enterpriseUser = {};
    // if (metadata.department) enterpriseUser.department = metadata.department;
    // if (metadata.employee_id) enterpriseUser.employeeNumber = metadata.employee_id;
    // if (metadata.cost_center) enterpriseUser.costCenter = metadata.cost_center;
    //
    // if (Object.keys(enterpriseUser).length > 0) {
    //     scimUser.schemas.push(SCIM_SCHEMA.ENTERPRISE_USER);
    //     scimUser[SCIM_SCHEMA.ENTERPRISE_USER] = enterpriseUser;
    // }

    return scimUser;
}

/**
 * @param {ScimUserPayload} scimUser
 * @returns {boolean}
 */
function hasRequiredIdentity(scimUser) {
    return (
        typeof scimUser.userName === 'string' &&
        scimUser.userName.trim().length > 0
    );
}

/**
 * externalId (the Auth0 user_id) is the correlation key the template relies on
 * to match a remote SCIM resource and to safely reconcile create conflicts.
 * A malformed event with no user_id yields no externalId.
 *
 * @param {ScimUserPayload} scimUser
 * @returns {boolean}
 */
function hasCorrelationKey(scimUser) {
    return (
        typeof scimUser.externalId === 'string' &&
        scimUser.externalId.trim().length > 0
    );
}

// ---------------------------------------------------------------------------
// SCIM lookup
// ---------------------------------------------------------------------------

/**
 * @param {Config} config
 * @param {ScimUserPayload} scimUser
 * @returns {Promise<ScimUser | null>}
 */
async function findUser(config, scimUser) {
    let shouldTryUserName = !scimUser.externalId;

    if (scimUser.externalId) {
        try {
            const byExternalId = await searchUser(
                config,
                'externalId',
                scimUser.externalId
            );
            if (byExternalId) return byExternalId;
        } catch (err) {
            // Fall back to userName search on ANY 400: servers signal an
            // unsupported externalId filter inconsistently (bare 400, varied
            // scimType). Our filter is escaped, so a 400 here means "externalId
            // filtering unsupported", not bad syntax. A 400 on userName still throws.
            if (/** @type {ScimError} */ (err).status !== HTTP.BAD_REQUEST)
                throw err;
            shouldTryUserName = true;
        }
    }

    if (!shouldTryUserName) return null;

    if (!scimUser.userName) {
        if (scimUser.externalId) {
            throw new Error(
                'SCIM server rejected externalId filtering and no userName fallback is available'
            );
        }
        return null;
    }

    return searchUser(config, 'userName', scimUser.userName);
}

/**
 * @param {Config} config
 * @param {string} attribute
 * @param {string | undefined} value
 * @returns {Promise<ScimUser | null>}
 */
async function searchUser(config, attribute, value) {
    if (!value) return null;

    const filter = `${attribute} eq "${escapeScimFilterValue(value)}"`;
    const res = await request(
        config,
        'GET',
        `/Users?filter=${encodeURIComponent(filter)}`
    );

    if (res.status === HTTP.OK) {
        // Throw on a malformed ListResponse rather than risk correlating
        // against a bad id; an empty list is a legitimate no-match.
        const users = parseScimList(await readJsonSafely(res));
        if (!users)
            throw scimShapeError(
                `GET /Users?filter=${attribute} eq`,
                res,
                'a ListResponse whose "Resources" entries each have a string "id" (RFC 7644 §3.4.2)'
            );
        return users[0] ?? null;
    }

    throw await scimError(`GET /Users?filter=${attribute} eq`, res);
}

// ---------------------------------------------------------------------------
// SCIM HTTP
// ---------------------------------------------------------------------------

/**
 * @param {Config} config - Resolved config from readConfig().
 * @param {string} method - HTTP method.
 * @param {string} path - Path appended to scimBaseUrl.
 * @param {*} [body] - Optional request body; omitted for GET/DELETE.
 * @returns {Promise<ScimResponse>}
 */
async function request(config, method, path, body) {
    let lastError;

    for (let attempt = 0; attempt <= config.scimMaxRetries; attempt++) {
        try {
            const res = await fetchWithTimeout(
                `${config.scimBaseUrl}${path}`,
                {
                    method,
                    headers: {
                        'Content-Type': 'application/scim+json',
                        Accept: 'application/scim+json',
                        Authorization: `Bearer ${config.scimBearerToken}`,
                    },
                    body: body === undefined ? undefined : JSON.stringify(body),
                },
                config.scimTimeoutMs
            );

            if (
                !isRetryableStatus(res.status) ||
                attempt === config.scimMaxRetries
            )
                return res;
        } catch (err) {
            lastError = err;
            if (attempt === config.scimMaxRetries) throw err;
        }

        await sleep(backoffMs(attempt));
    }

    throw lastError ?? new Error('SCIM request exhausted retries');
}

/**
 * @param {string} url
 * @param {RequestInit} init
 * @param {number} timeoutMs
 * @returns {Promise<ScimResponse>}
 */
async function fetchWithTimeout(url, init, timeoutMs) {
    const abortController = new AbortController();
    const timer = setTimeout(() => abortController.abort(), timeoutMs);
    try {
        // The editor's ambient `Response` type is minimal and omits `status`;
        // the real Actions runtime returns a standard WHATWG Response that has
        // it. Assert the shape this template reads (see ScimResponse typedef).
        return /** @type {ScimResponse} */ (
            await fetch(url, { ...init, signal: abortController.signal })
        );
    } finally {
        clearTimeout(timer);
    }
}

/**
 * @param {number} status
 * @returns {boolean}
 */
function isRetryableStatus(status) {
    return (
        status === HTTP.TOO_MANY_REQUESTS ||
        status >= HTTP.SERVER_ERROR_THRESHOLD
    );
}

/**
 * @param {number} attempt
 * @returns {number}
 */
function backoffMs(attempt) {
    return Math.min(
        DEFAULTS.RETRY_BASE_DELAY_MS * 2 ** attempt,
        DEFAULTS.RETRY_MAX_DELAY_MS
    );
}

/** @param {number} ms */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * @param {string} scimId
 * @returns {string}
 */
function userPath(scimId) {
    return `/Users/${encodeURIComponent(scimId)}`;
}

/**
 * @param {string} label
 * @param {ScimResponse} res
 * @returns {Promise<ScimError>}
 */
async function scimError(label, res) {
    const { scimType, detail } = parseScimErrorBody(await readJsonSafely(res));
    return Object.assign(
        new Error(
            scimType
                ? `SCIM ${label} -> ${res.status} [${scimType}]`
                : `SCIM ${label} -> ${res.status}`
        ),
        {
            status: res.status,
            scimType,
            detail,
        }
    );
}

/**
 * Raised on a success status with an invalid body. `expected` names the shape
 * the destination should have returned; the message cites the SCIM spec so an
 * operator can check their server against it. Built from the status alone, since
 * readJsonSafely already consumed the body. Same shape as scimError so
 * errorLogFields() reports it uniformly.
 *
 * @param {string} label
 * @param {ScimResponse} res
 * @param {string} expected
 * @returns {ScimError}
 */
function scimShapeError(label, res, expected) {
    return Object.assign(
        new Error(
            `SCIM ${label} -> ${res.status} [invalid response shape] expected ${expected}; see ${SCIM_SPEC_URL}`
        ),
        {
            status: res.status,
            scimType: 'invalidResponseShape',
        }
    );
}

/**
 * Parse a response body, returning `null` instead of throwing on invalid JSON.
 * Returns `unknown`; callers validate via parseScimUser/parseScimList first.
 * @param {ScimResponse} res
 * @returns {Promise<unknown>}
 */
async function readJsonSafely(res) {
    try {
        return await res.json();
    } catch {
        return null;
    }
}

// ---------------------------------------------------------------------------
// SCIM response validation
//
// A 2xx does not guarantee a well-formed body. These helpers narrow an
// `unknown` body to the correlation slice the template relies on, returning
// `null` on anything unexpected so callers decide explicitly (skip vs. throw).
// ---------------------------------------------------------------------------

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isObject(value) {
    return typeof value === 'object' && value !== null;
}

/**
 * `id` is mandatory (builds the PUT/DELETE path); `externalId` is optional.
 * Returns null when `id` is missing or not a non-empty string.
 *
 * @param {unknown} body
 * @returns {ScimUser | null}
 */
function parseScimUser(body) {
    if (!isObject(body)) return null;
    const { id, externalId } = body;
    if (typeof id !== 'string' || id.trim().length === 0) return null;
    return {
        id,
        externalId: typeof externalId === 'string' ? externalId : undefined,
    };
}

/**
 * Returns null for an invalid body (Resources missing/not an array, or a
 * member with no usable id) so the caller can throw; an empty array is a
 * legitimate no-match.
 *
 * @param {unknown} body
 * @returns {ScimUser[] | null}
 */
function parseScimList(body) {
    if (!isObject(body) || !Array.isArray(body.Resources)) return null;
    const users = [];
    for (const resource of body.Resources) {
        const user = parseScimUser(resource);
        if (!user) return null;
        users.push(user);
    }
    return users;
}

/**
 * Extract the diagnostic fields a SCIM server may return in an error body.
 * Everything is optional; missing or mistyped values come back undefined.
 *
 * @param {unknown} body
 * @returns {{ scimType?: string, detail?: string }}
 */
function parseScimErrorBody(body) {
    if (!isObject(body)) return {};
    const scimType =
        typeof body.scimType === 'string' ? body.scimType : undefined;
    let detail = typeof body.detail === 'string' ? body.detail : undefined;
    if (detail === undefined && Array.isArray(body.Errors)) {
        const first = body.Errors[0];
        if (isObject(first) && typeof first.description === 'string') {
            detail = first.description;
        }
    }
    return { scimType, detail };
}

/**
 * @param {string} value
 * @returns {string}
 */
function escapeScimFilterValue(value) {
    return String(value)
        .replace(/\\/g, '\\\\')
        .replace(/"/g, '\\"')
        .replace(
            /[\u0000-\u001f]/g,
            (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`
        );
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/**
 * @param {'info' | 'warn' | 'error'} level
 * @param {string} msg
 * @param {Record<string, unknown>} [extra]
 */
function log(level, msg, extra = {}) {
    const line = JSON.stringify({ level, msg, ...extra });
    if (level === 'error') console.error(line);
    else console.log(line);
}

/**
 * @param {ScimError} err
 */
function errorLogFields(err) {
    /** @type {Record<string, unknown>} */
    const fields = {
        status: err?.status,
        scimType: err?.scimType,
        errorMessage: err?.message ?? String(err),
    };

    if (err?.cause) {
        fields.causeStatus = err.cause.status;
        fields.causeScimType = err.cause.scimType;
        fields.causeMessage = err.cause.message;
    }

    return fields;
}
