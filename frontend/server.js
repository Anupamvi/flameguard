const http = require("http");
const next = require("next");

const port = Number.parseInt(process.env.PORT || "3000", 10);
const hostname = "0.0.0.0";

const app = next({
  dev: false,
  hostname,
  port,
});

const handle = app.getRequestHandler();

function stripPoweredBy(res) {
  const originalWriteHead = res.writeHead.bind(res);

  res.writeHead = (...args) => {
    res.removeHeader("X-Powered-By");
    res.removeHeader("x-powered-by");

    const headersArgIndex =
      args.length >= 2 && typeof args[1] === "object"
        ? 1
        : args.length >= 3 && typeof args[2] === "object"
          ? 2
          : -1;

    if (headersArgIndex !== -1) {
      const headers = { ...args[headersArgIndex] };
      delete headers["X-Powered-By"];
      delete headers["x-powered-by"];
      args[headersArgIndex] = headers;
    }

    return originalWriteHead(...args);
  };
}

app.prepare().then(() => {
  http
    .createServer((req, res) => {
      stripPoweredBy(res);
      Promise.resolve(handle(req, res)).catch((error) => {
        console.error(error);
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end("Internal Server Error");
        }
      });
    })
    .listen(port, hostname, () => {
      console.log(`> Ready on http://${hostname}:${port}`);
    });
});