// Refresh the browser session and issue a new NGM launch ticket without
// exposing the ticket or account credentials in stdout.

const account = process.env.MAPLE_ACCOUNT_EMAIL;
const password = process.env.MAPLE_ACCOUNT_PASSWORD;
const endpoint = process.env.MAPLE_CDP_ENDPOINT || "http://127.0.0.1:9229";
const loginUrl =
  "https://galaxy.games.gamania.com/webapi/view/login/mstc" +
  `?redirect_url=${encodeURIComponent("https://maplestoryclassic.beanfun.com/Main")}` +
  `&flow_nonce=${Date.now()}`;

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
socket.addEventListener("message", ({data}) => {
  const message = JSON.parse(data);
  if (!message.id || !pending.has(message.id)) return;
  const {resolve, reject} = pending.get(message.id);
  pending.delete(message.id);
  message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
});

function send(method, params = {}) {
  const id = nextId++;
  socket.send(JSON.stringify({id, method, params}));
  return new Promise((resolve, reject) => pending.set(id, {resolve, reject}));
}

async function evaluate(expression, contextId) {
  const result = await send("Runtime.evaluate", {
    expression,
    contextId,
    returnByValue: true,
  });
  return result.result.value;
}

async function waitFor(predicate, description, timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for ${description}`);
}

async function frameTree() {
  return (await send("Page.getFrameTree")).frameTree;
}

function flattenFrames(root) {
  const result = [];
  const queue = [root];
  while (queue.length) {
    const node = queue.shift();
    result.push(node.frame);
    queue.push(...(node.childFrames || []));
  }
  return result;
}

async function currentLoginFrame() {
  const frames = flattenFrames(await frameTree());
  return frames.find((frame) =>
    frame.url.includes("/login/id-pass_form_newBF.aspx")
  ) || null;
}

async function submitLoginFrame(loginFrame) {
  if (!account || !password) {
    throw new Error(
      "Maple account environment variables are required for a fresh login",
    );
  }
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  const {executionContextId} = await send("Page.createIsolatedWorld", {
    frameId: loginFrame.id,
    worldName: `hk-login-${loginFrame.id}`,
  });
  const submitted = await evaluate(`((account, password) => {
    document.querySelector('#DivMsgBoxBtn')?.click();
    const accountInput = document.querySelector('#t_AccountID');
    const passwordInput = document.querySelector('#t_Password');
    const submit = document.querySelector('#btn_login');
    if (!accountInput || !passwordInput || !submit) return false;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    for (const [input, value] of [[accountInput, account], [passwordInput, password]]) {
      setter.call(input, value);
      input.dispatchEvent(new Event('input', {bubbles: true}));
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }
    submit.click();
    return true;
  })(${JSON.stringify(account)}, ${JSON.stringify(password)})`, executionContextId);
  if (!submitted) throw new Error("The HK login form was incomplete");
}

await send("Page.enable");
await send("Runtime.enable");
if (process.env.MAPLE_FORCE_RELOGIN === "1") {
  await send("Network.enable");
  await send("Network.clearBrowserCookies");
}
let previousArgument = null;
try {
  previousArgument = await evaluate(
    "typeof globalThis.NgmLayerHelper?.argument === 'string' " +
      "? globalThis.NgmLayerHelper.argument : null",
  );
} catch {
  // The current page may not expose the NGM helper yet.
}
let authenticatedMain = false;
try {
  authenticatedMain = await evaluate(
    "Boolean(document.querySelector('#gamestart'))",
  );
} catch {
  // A navigation may be replacing the current document.
}

if (!authenticatedMain) {
  await send("Page.navigate", {url: loginUrl});

  await waitFor(
    () => evaluate("Boolean(document.querySelector('.btnLogin-beanfun'))"),
    "the Galaxy Beanfun login button",
  );
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  await evaluate("document.querySelector('.btnLogin-beanfun').click(); true");

  let loginFrame = null;
  await waitFor(async () => {
    loginFrame = await currentLoginFrame();
    if (loginFrame) return true;
    return evaluate("Boolean(document.querySelector('#gamestart'))");
  }, "the HK login form or authenticated main page");

  if (loginFrame) {
    await submitLoginFrame(loginFrame);
  }
}

await waitFor(
  () => evaluate("Boolean(document.querySelector('#gamestart'))"),
  "the MapleStory Game Start button",
);
await send("Page.reload", {ignoreCache: true});
await waitFor(
  () => evaluate("Boolean(document.querySelector('#gamestart'))"),
  "the refreshed MapleStory Game Start button",
);
await new Promise((resolve) => setTimeout(resolve, 1_500));
await evaluate("document.querySelector('#gamestart').click(); true");

await waitFor(
  () => evaluate("Boolean(document.querySelector('.btnLogin-beanfun'))"),
  "the post-start Galaxy Beanfun button",
);
await new Promise((resolve) => setTimeout(resolve, 1_500));
await evaluate("document.querySelector('.btnLogin-beanfun').click(); true");

let postAuthorizationLoginFrame = null;
await waitFor(async () => {
  postAuthorizationLoginFrame = await currentLoginFrame();
  if (postAuthorizationLoginFrame) return true;
  return evaluate("Boolean(document.querySelector('#gamestart'))");
}, "the authenticated main page or repeated HK login form");
if (postAuthorizationLoginFrame) {
  await submitLoginFrame(postAuthorizationLoginFrame);
}

await waitFor(
  () => evaluate("Boolean(document.querySelector('#gamestart'))"),
  "the authenticated main page after game authorization",
);

const ticketArgument = await waitFor(
  () => evaluate(
    "typeof globalThis.NgmLayerHelper?.argument === 'string' && " +
      "globalThis.NgmLayerHelper.argument.includes('-passarg:') " +
      "? globalThis.NgmLayerHelper.argument : ''",
  ),
  "a valid NGM launch ticket",
);

socket.close();
console.log(JSON.stringify({
  ticketReady: true,
  ticketChanged: previousArgument === null || previousArgument !== ticketArgument,
  forcedRelogin: process.env.MAPLE_FORCE_RELOGIN === "1",
}));
