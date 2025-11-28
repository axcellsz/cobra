export default {
  async fetch(request, env, ctx) {
    return new Response("WOLLEZ", {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  },
};
