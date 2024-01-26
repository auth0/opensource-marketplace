/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/os-marketplace/blob/main/templates/simple-domain-allowlist-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // ensure user email is present
    if (!event.user.email) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('Email is invalid');
    }

    // ensure the user has verified their email address
    if (!event.user.email_verified) {
        api.access.deny('Email is unverified');
    }

    // ensure the allowed domains are configured
    if (!event.secrets.ALLOWED_DOMAINS) {
        return api.access.deny('Configuration error');
    }

    // parse the allow list of domain and ensure there is at least one
    const domains = event.secrets.ALLOWED_DOMAINS.split(',').map((domain) =>
        domain.trim().toLowerCase()
    );
    if (!domains) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('Configuration error');
    }

    // ensure a reasonable format for the email
    const splitEMail = event.user.email.split('@');
    if (splitEMail.length !== 2) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('Email is invalid');
    }

    // if the email domain is not explicitly in our allow list, deny access
    const domain = splitEMail[1].toLowerCase();
    if (!domains.includes(domain)) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('Email domain is prohibited');
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
