/**
 * Handler that will be called during the execution of a PreUserRegistration flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/simple-domain-allowlist-PRE_USER_REGISTRATION ---
 *
 * @param {Event} event - Details about the context and user that is attempting to register.
 * @param {PreUserRegistrationAPI} api - Interface whose methods can be used to change the behavior of the signup.
 */
exports.onExecutePreUserRegistration = async (event, api) => {
    // ensure user email is present
    if (!event.user.email) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('invalid_email', 'Email is invalid');
    }

    if (!event.secrets.ALLOWED_DOMAINS) {
        return api.access.deny('invalid_config', 'Invalid configuration');
    }

    // parse the allow list of domain and ensure there is at least one
    const domains = event.secrets.ALLOWED_DOMAINS.split(',').map((domain) =>
        domain.trim().toLowerCase()
    );
    if (!domains) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('invalid_config', 'Invalid configuration');
    }

    // ensure a reasonable format for the email
    const splitEMail = event.user.email.split('@');
    if (splitEMail.length !== 2) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('invalid_email', 'Email is invalid');
    }

    // if the email domain is not explicitly in our allow list, deny access
    const domain = splitEMail[1].toLowerCase();
    if (!domains.includes(domain)) {
        // note that userMessage (the second parameter) is displayed in red on the failed sign-up prompt
        return api.access.deny('invalid_domain', 'Email domain is prohibited');
    }
};
