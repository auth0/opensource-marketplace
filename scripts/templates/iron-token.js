import * as Iron from "@hapi/iron"

const TOKEN_TTL_MS = 900000;

export const mintIronToken = async () => {
    const payload = { issuer: env.SERVICE_NAME };
  return await Iron.seal(
    payload,
    { id: process.env.IRON_KEY_ID, secret: process.env.IRON_KEY_SECRET },
    {
      ...Iron.defaults,
      ttl: TOKEN_TTL_MS
    }
  );
}