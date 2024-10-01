/**
 * Constants for session metadata field names.
 * In you can create those metadata values in Organizations, Connections or inside Applications in Auth0. If the metadata is created, this action will use it
 */
const IDLE_LIFETIME_FIELD = 'idle_lifetime';
const ABSOLUTE_LIFETIME_FIELD = 'absolute_lifetime';

/**
 * Handler that will be called during the execution of a PostLogin flow.
 *
 * @param {Event} event - Details about the user and the context in which they are logging in.
 * @param {PostLoginAPI} api - Interface whose methods can be used to change the behavior of the login.
 */
exports.onExecutePostLogin = async (event, api) => {
  const currentTime = Date.now();

  // Get organization, client, or connection metadata (organization takes precedence if present)
  const metadata = event.organization?.metadata || event.client?.metadata || event.connection?.metadata;

  if (metadata) {
    // Set idle timeout using the metadata field defined in IDLE_LIFETIME_FIELD
    const idleTimeout = Number(metadata[IDLE_LIFETIME_FIELD]);
    if (idleTimeout) {
      api.session.setIdleExpiresAt(currentTime + idleTimeout);
    }

    // Set absolute timeout using the metadata field defined in ABSOLUTE_LIFETIME_FIELD
    const absoluteTimeout = Number(metadata[ABSOLUTE_LIFETIME_FIELD]);
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
