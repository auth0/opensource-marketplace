const xmldom = require('@xmldom/xmldom');
const xpath = require('xpath');

// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/soap-webservice-POST_LOGIN ---
/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */

const FETCH_TIMEOUT = 1000; // 1s

async function fetchRoles(domain, action) {
    // make sure the request times out after `FETCH_TIMEOUT`ms
    const controller = new AbortController();
    setTimeout(() => controller.abort(), FETCH_TIMEOUT);

    const response = await fetch(`https://${domain}/RoleService.svc`, {
        method: 'POST',
        signal: controller.signal,
        headers: {
            'Content-Type': 'text/xml; charset=utf-8',
            SOAPAction: action,
        },
    });

    const body = await response.text();
    const parser = new xmldom.DOMParser();
    const doc = parser.parseFromString(body);
    const roles = xpath
        .select("//*[local-name(.)='string']", doc)
        .map(function (node) {
            return node.textContent;
        });
    return roles;
}

exports.onExecutePostLogin = async (event, api) => {
    const domain = event.secrets.DOMAIN;
    if (!domain) {
        return api.access.deny('invalid server domain');
    }

    let namespace = event.secrets.ID_TOKEN_NAMESPACE || '';
    if (namespace && !namespace.endsWith('/')) {
        namespace += '/';
    }

    const action = event.secrets.SOAP_ACTION;
    if (!action) {
        return api.access.deny('invalid soap action');
    }

    try {
        const roles = await fetchRoles(domain, action);

        // at this point, you can use the roles, for example you can set a
        // custom claim on the id token
        api.idToken.setCustomClaim(`${namespace}roles`, roles);
    } catch (error) {
        // during debugging, you can uncomment the line below to see what the error is:
        // console.log('failed to fetch roles, error:', error);

        return api.access.deny('action failed');
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
