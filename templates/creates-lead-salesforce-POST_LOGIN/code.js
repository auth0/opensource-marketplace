/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * --- AUTH0 ACTIONS TEMPLATE https://github.com/auth0/opensource-marketplace/blob/main/templates/creates-lead-salesforce-POST_LOGIN ---
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    // if a lead has already been recorded then end the action successfully
    if (event.user.app_metadata.recordedAsLead) {
        return;
    }
    //Populate the variables below with appropriate values, failing if any secrets are missing
    const sfDomain = event.secrets.SALESFORCE_DOMAIN;
    if (!sfDomain) {
        console.log(`Unable to create lead: Salesforce domain not configured`);
        return;
    }
    const sfClientId = event.secrets.SALESFORCE_CLIENT_ID;
    if (!sfClientId) {
        console.log(
            `Unable to create lead: Salesforce client id not configured`
        );
        return;
    }
    const sfClientSecret = event.secrets.SALESFORCE_CLIENT_SECRET;
    if (!sfClientSecret) {
        console.log(
            `Unable to create lead: Salesforce client secret not configured`
        );
        return;
    }
    const sfCompany = event.secrets.SALESFORCE_COMPANY;
    if (!sfCompany) {
        console.log(`Unable to create lead: Salesforce company not configured`);
        return;
    }

    // fetch the token from the cache or regenreate it if it cannot be retrieved, see
    // https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_endpoints.htm
    const fetchAccessToken = async () => {
        const cachedToken = api.cache.get('sf_access_token');
        if (cachedToken) {
            return cachedToken.value;
        }
        const sfLogin = `https://${sfDomain}/services/oauth2/token`;
        const body = new FormData();
        body.set('grant_type', 'client_credentials');
        body.set('client_id', sfClientId);
        body.set('client_secret', sfClientSecret);
        // force hourly refresh on a per-host basis
        const expiry = Date.now() + 3600000;
        const response = await fetch(sfLogin, {
            method: 'POST',
            body: body,
        });
        if (!response.ok) {
            throw new Error('Unable to fetch token');
        }
        const data = await response.json();
        api.cache.set('sf_access_token', data.access_token, {
            expires_at: expiry,
        });
        return data.access_token;
    };

    //See http://www.salesforce.com/us/developer/docs/api/Content/sforce_api_objects_lead.htm
    const createLead = async (access_token) => {
        // see https://developer.salesforce.com/docs/atlas.en-us.object_reference.meta/object_reference/sforce_api_objects_lead.htm
        const body = {
            LastName: event.user.name || event.user.email,
            Company: sfCompany,
            Email: event.user.email,
        };
        const headers = {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${access_token}`,
        };
        const sfLead = `https://${sfDomain}/services/data/v59.0/sobjects/Lead`;
        const response = await fetch(sfLead, {
            method: 'POST',
            body: JSON.stringify(body),
            headers: headers,
        });
        if (!response.ok) {
            throw new Error('Unable to create lead');
        }
    };

    try {
        const token = await fetchAccessToken();
        await createLead(token);

        // if no errors were raised, the lead was created
        api.user.setAppMetadata('recordedAsLead', true);
    } catch (error) {
        // fail gracefully *withough* recording that lead generation has
        // completed. Failing to handle these errors here would result
        // in a failedl login flow, which we do not want.
        return;
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
