// Keep proxy authentication active for the existing CDP-controlled browser.
// Credentials are read from the environment and are never printed.

const username = process.env.MAPLE_PROXY_USER;
const password = process.env.MAPLE_PROXY_PASSWORD;
const endpoint = process.env.MAPLE_CDP_ENDPOINT || "http://127.0.0.1:9229";
const loginUrl =
  "https://galaxy.games.gamania.com/webapi/view/login/mstc" +
  "?redirect_url=https://maplestoryclassic.beanfun.com/Main";

if (!username || !password) {
  throw new Error("Proxy credentials are missing from the environment");
}

const targets = await (await fetch(`${endpoint}/json`)).json();
const target = targets.find((entry) => entry.type === "page");
if (!target) throw new Error("No Chromium page target was found");

const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, {once: true});
  socket.addEventListener("error", reject, {once: true});
});

let nextId = 1;
const pending = new Map();
function send(method, params = {}) {
  const id = nextId++;
  socket.send(JSON.stringify({id, method, params}));
  return new Promise((resolve, reject) => pending.set(id, {resolve, reject}));
}

socket.addEventListener("message", async ({data}) => {
  const message = JSON.parse(data);
  if (message.id) {
    const callback = pending.get(message.id);
    if (!callback) return;
    pending.delete(message.id);
    if (message.error) callback.reject(new Error(JSON.stringify(message.error)));
    else callback.resolve(message.result);
    return;
  }
  if (message.method === "Fetch.authRequired") {
    const authChallengeResponse = message.params.authChallenge.source === "Proxy"
      ? {response: "ProvideCredentials", username, password}
      : {response: "Default"};
    await send("Fetch.continueWithAuth", {
      requestId: message.params.requestId,
      authChallengeResponse,
    });
  } else if (message.method === "Fetch.requestPaused") {
    await send("Fetch.continueRequest", {requestId: message.params.requestId});
  }
});

await send("Page.enable");
await send("Fetch.enable", {
  handleAuthRequests: true,
  patterns: [{urlPattern: "*"}],
});
await send("Page.navigate", {url: loginUrl});
console.log("browser_proxy_auth ready=true");

await new Promise((resolve) => setTimeout(resolve, 30 * 60 * 1000));
socket.close();
