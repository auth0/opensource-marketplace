/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/guardian-multifactor-ip-range-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    const ipaddr = require('ipaddr.js');

    // get the trusted CIDR and ensure it is valid
    const corp_network = event.secrets.TRUSTED_CIDR;
    if (!corp_network) {
        return api.access.deny('Invalid configuration');
    }

    // parse the request IP from and ensure it is valid
    let current_ip;
    try {
        current_ip = ipaddr.parse(event.request.ip);
    } catch (error) {
        return api.access.deny('Invalid request');
    }

    // parse the CIDR and ensure validity
    let cidr;
    try {
        cidr = ipaddr.parseCIDR(corp_network);
    } catch (error) {
        return api.access.deny('Invalid configuration');
    }

    // enforce guardian MFA if the IP is not in the trusted allocation
    if (!current_ip.match(cidr)) {
        api.multifactor.enable('guardian', { allowRememberBrowser: false });
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
