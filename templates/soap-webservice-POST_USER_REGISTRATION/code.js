const xmldom = require('@xmldom/xmldom');
const xpath = require('xpath');

// --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/soap-webservice-POST_USER_REGISTRATION ---
/**
 * Handler that will be called during the execution of a PostUserRegistration flow.
 *
 * @param {Event} event - Details about the context and user that has registered.
 * @param {PostUserRegistrationAPI} api - Methods and utilities to help change the behavior after a signup.
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

exports.onExecutePostUserRegistration = async (event, api) => {
    const domain = event.secrets.DOMAIN;
    if (!domain) {
        return;
    }

    const action = event.secrets.SOAP_ACTION;
    if (!action) {
        return;
    }

    try {
        const roles = await fetchRoles(domain, action);

        // at this point, you can use the roles, for example you can set a
        // custom claim on the id token
    } catch (error) {
        // during debugging, you can uncomment the line below to see what the error is:
        // console.log('failed to fetch roles, error:', error);

        return;
    }
};
