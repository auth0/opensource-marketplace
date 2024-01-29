---
to: "<%= trigger == 'POST_CHANGE_PASSWORD' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
 * Handler that will be called during the execution of a PostChangePassword flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/<%= fileName %>-<%= trigger %> ---
 *
 * @param {Event} event - Details about the user and the context in which the change password is happening.
 * @param {PostChangePasswordAPI} api - Methods and utilities to help change the behavior after a user changes their password.
 */
exports.onExecutePostChangePassword = async (event, api) => {
};
