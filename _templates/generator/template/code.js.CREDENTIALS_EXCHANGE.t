---
to: "<%= trigger == 'CREDENTIALS_EXCHANGE' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
 * Handler that will be called during the execution of a Client Credentials exchange.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/<%= fileName %>-<%= trigger %> ---
 *
 * @param {Event} event - Details about client credentials grant request.
 * @param {CredentialsExchangeAPI} api - Interface whose methods can be used to change the behavior of client credentials grant.
 */
exports.onExecuteCredentialsExchange = async (event, api) => {
};
