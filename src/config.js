export function loadConfig(env) {
  return {
    API_KEY: env.API_KEY,
    BASE_API_URL: env.BASE_API_URL,
    BASE_CIAM_URL: env.BASE_CIAM_URL,
    UA: env.UA,
    BASIC_AUTH: env.BASIC_AUTH,
    AES_KEY_ASCII: env.AES_KEY_ASCII,
    ENCRYPTED_FIELD_KEY: env.ENCRYPTED_FIELD_KEY,
    AX_FP_KEY: env.AX_FP_KEY,
    XDATA_KEY: env.XDATA_KEY,
    AX_API_SIG_KEY: env.AX_API_SIG_KEY,
    X_API_BASE_SECRET: env.X_API_BASE_SECRET,
  };
}
