---
to: "<%= trigger == 'POST_USER_REGISTRATION' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
 * Handler that will be called during the execution of a PostUserRegistration flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/<%= fileName %>-<%= trigger %> ---
 *
 * @param {Event} event - Details about the context and user that has registered.
 * @param {PostUserRegistrationAPI} api - Methods and utilities to help change the behavior after a signup.
 */
exports.onExecutePostUserRegistration = async (event, api) => {
};
