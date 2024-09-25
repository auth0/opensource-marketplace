/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
    const currentTime = Date.now();
  
    // Get organization or client metadata (organization takes precedence if present)
    const metadata = event.organization?.metadata || event.client?.metadata || event.connection?.metadata;
  
    if (metadata) {
      // Set idle timeout
      const idleTimeout = Number(metadata.idle_lifetime);
      if (idleTimeout) {
        api.session.setIdleExpiresAt(currentTime + idleTimeout);
      }
  
      // Set absolute timeout
      const absoluteTimeout = Number(metadata.absolute_lifetime);
      const createdAt = event.session?.created_at ? new Date(event.session.created_at).getTime() : null;
  
      if (absoluteTimeout && createdAt) {
        api.session.setExpiresAt(createdAt + absoluteTimeout);
      }
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
