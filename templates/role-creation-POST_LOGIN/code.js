/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/role-creation-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // Roles should only be set to verified users.
    if (!event.user.email || !event.user.email_verified) {
        return api.access.deny('access denied');
    }

    // get the special role name, value, and users to which should be granted.
    const specialName = event.secrets.SPECIAL_ROLE_NAME;
    if (!specialName) {
        return api.access.deny('Invalid configuration');
    }

    // get the special role values and ensure they are valid
    const specialValues = event.secrets.SPECIAL_ROLE_VALUE?.split(',').map(
        (v) => v.trim()
    );
    if (!specialValues) {
        return api.access.deny('Invalid configuration');
    }

    // get the special role users, ensuring they are valid
    const specialRoleUsers = event.secrets.SPECIAL_ROLE_USERS?.split(',').map(
        (u) => u.trim()
    );
    if (!specialRoleUsers) {
        return api.access.deny('Invalid configuration');
    }

    // if this user is a special user set their custom claim
    if (specialRoleUsers.includes(event.user.email)) {
        api.idToken.setCustomClaim(specialName, specialValues);
        api.accessToken.setCustomClaim(specialName, specialValues);
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
