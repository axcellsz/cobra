export const TokensKV = {
  async getAll(env) {
    const raw = await env.Pages2.get("REFRESH_TOKENS");
    return raw ? JSON.parse(raw) : [];
  },

  async saveAll(env, data) {
    await env.Pages2.put("REFRESH_TOKENS", JSON.stringify(data));
  },

  async getActive(env) {
    const n = await env.Pages2.get("ACTIVE_NUMBER");
    return n;
  },

  async setActive(env, number) {
    await env.Pages2.put("ACTIVE_NUMBER", String(number));
  }
};
