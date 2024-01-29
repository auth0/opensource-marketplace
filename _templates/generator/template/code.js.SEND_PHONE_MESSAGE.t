---
to: "<%= trigger == 'SEND_PHONE_MESSAGE' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
 * Handler that will be called during the execution of a SendPhoneMessage flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/<%= fileName %>-<%= trigger %> ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {SendPhoneMessageAPI} api - Methods and utilities to help change the behavior of sending a phone message.
 */
exports.onExecuteSendPhoneMessage = async (event, api) => {
};
