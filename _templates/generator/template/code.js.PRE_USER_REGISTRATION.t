---
to: "<%= trigger == 'PRE_USER_REGISTRATION' ? `templates/${fileName}-${trigger}/code.js` : null %>"
---

/**
 * Handler that will be called during the execution of a PreUserRegistration flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/<%= fileName %>-<%= trigger %> ---
 *
 * @param {Event} event - Details about the context and user that is attempting to register.
 * @param {PreUserRegistrationAPI} api - Interface whose methods can be used to change the behavior of the signup.
 */
exports.onExecutePreUserRegistration = async (event, api) => {
};
