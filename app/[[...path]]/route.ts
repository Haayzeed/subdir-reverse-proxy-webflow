import { NextRequest } from "next/server";

const PROXY_TARGET_URL = process.env.PROXY_TARGET_URL;

// Validate environment variable at startup
if (!PROXY_TARGET_URL) {
  throw new Error("PROXY_TARGET_URL environment variable is required");
}

let parsedTargetUrl: URL;
try {
  parsedTargetUrl = new URL(PROXY_TARGET_URL);
} catch {
  throw new Error("PROXY_TARGET_URL must be a valid URL");
}

if (!["http:", "https:"].includes(parsedTargetUrl.protocol)) {
  throw new Error("PROXY_TARGET_URL must use http or https protocol");
}

// Path of the origin site, without a trailing slash (e.g. "/bank-codes")
const ORIGIN_BASE_PATH = parsedTargetUrl.pathname.replace(/\/+$/, "");

// A last path segment like "s.css" or "sitemap-1.xml" is a file; anything else is a page
const FILE_EXTENSION = /\.[A-Za-z0-9]{1,10}$/;

// How many trailing-slash redirects from the origin to follow before giving up
const MAX_ORIGIN_REDIRECTS = 3;

/**
 * Validates and sanitizes path segments to prevent path traversal attacks.
 * Returns null if the path contains malicious segments.
 */
function sanitizePath(segments: string[]): string | null {
  for (const segment of segments) {
    // Block path traversal attempts
    if (segment === ".." || segment === ".") {
      return null;
    }

    // Block null bytes
    if (segment.includes("\0")) {
      return null;
    }

    // Decode and check for encoded traversal attempts
    try {
      const decoded = decodeURIComponent(segment);
      if (decoded.includes("..") || decoded.includes("\0")) {
        return null;
      }
    } catch {
      // Invalid encoding - reject
      return null;
    }
  }

  return segments.length > 0 ? `/${segments.join("/")}` : "";
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400 && status !== 304;
}

function stripTrailingSlash(pathname: string): string {
  return pathname.replace(/\/+$/, "");
}

/** True when the URL points inside the origin site this app proxies. */
function isOriginUrl(url: URL): boolean {
  return (
    url.host === parsedTargetUrl.host &&
    (url.pathname === ORIGIN_BASE_PATH ||
      url.pathname.startsWith(`${ORIGIN_BASE_PATH}/`))
  );
}

/**
 * Converts an origin URL into the matching path on the public site, so a
 * redirect never sends the visitor to the origin's own domain.
 */
function toPublicLocation(url: URL, publicBasePath: string): string {
  const rest = stripTrailingSlash(url.pathname.slice(ORIGIN_BASE_PATH.length));
  const path = `${publicBasePath}${rest}` || "/";
  return path + url.search + url.hash;
}

// Headers that should not be forwarded
const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "host",
]);

// Headers to exclude from response (fetch auto-decompresses, so encoding headers cause issues)
const EXCLUDED_RESPONSE_HEADERS = new Set([
  ...HOP_BY_HOP_HEADERS,
  "content-encoding",
  "content-length",
]);

type RouteContext = {
  params: Promise<{ path?: string[] }>;
};

async function proxyRequest(
  request: NextRequest,
  { params }: RouteContext
): Promise<Response> {
  const resolvedParams = await params;
  const pathSegments = resolvedParams.path || [];

  // Validate and sanitize path to prevent SSRF/path traversal
  const sanitizedPath = sanitizePath(pathSegments);
  if (sanitizedPath === null) {
    return new Response("Bad Request", { status: 400 });
  }

  const isReadOnly = request.method === "GET" || request.method === "HEAD";

  // Webflow removes the trailing slash before a request reaches this app, but
  // static hosts such as GitHub Pages only serve a page at its trailing-slash
  // URL and redirect to their own domain otherwise. So ask the origin for
  // pages with the slash put back, and for files exactly as requested.
  const lastSegment = pathSegments[pathSegments.length - 1] ?? "";
  const addTrailingSlash = !FILE_EXTENSION.test(lastSegment);

  // Construct target URL safely using URL API
  const targetUrlObj = new URL(PROXY_TARGET_URL!);
  targetUrlObj.pathname =
    ORIGIN_BASE_PATH + sanitizedPath + (addTrailingSlash ? "/" : "");

  // Safely copy query parameters from the request
  const requestUrl = new URL(request.url);
  targetUrlObj.search = requestUrl.search;

  // Forward headers, excluding hop-by-hop headers
  const headers = new Headers();
  for (const [key, value] of request.headers.entries()) {
    if (!HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  }

  // Set the host header to the target host
  headers.set("host", targetUrlObj.host);

  // Forward the request
  const fetchOptions: RequestInit & { duplex?: string } = {
    method: request.method,
    headers,
    redirect: "manual",
  };

  // Forward body for methods that support it
  if (!isReadOnly) {
    fetchOptions.body = request.body;
    fetchOptions.duplex = "half";
  }

  let currentUrl = targetUrlObj;
  let response = await fetch(currentUrl, fetchOptions);

  // A file with no extension (e.g. "about" served from about.html) is not
  // found at the trailing-slash URL, so try it once more without the slash.
  if (addTrailingSlash && isReadOnly && response.status === 404) {
    const withoutSlash = new URL(currentUrl);
    withoutSlash.pathname = ORIGIN_BASE_PATH + sanitizedPath;
    // Discard the first answer; if the page is missing here too, the
    // visitor gets the origin's own "not found" page from this request.
    void response.body?.cancel().catch(() => {});
    currentUrl = withoutSlash;
    response = await fetch(currentUrl, fetchOptions);
  }

  // If the origin only wants to add or remove a trailing slash, follow that
  // here instead of passing the redirect to the visitor's browser.
  for (
    let hop = 0;
    isReadOnly && isRedirect(response.status) && hop < MAX_ORIGIN_REDIRECTS;
    hop++
  ) {
    const location = response.headers.get("location");
    if (!location) break;

    const next = new URL(location, currentUrl);
    const onlySlashDiffers =
      isOriginUrl(next) &&
      next.pathname !== currentUrl.pathname &&
      stripTrailingSlash(next.pathname) ===
        stripTrailingSlash(currentUrl.pathname);
    if (!onlySlashDiffers) break;

    void response.body?.cancel().catch(() => {});
    currentUrl = next;
    response = await fetch(currentUrl, fetchOptions);
  }

  // Build response headers, excluding problematic headers
  const responseHeaders = new Headers();
  for (const [key, value] of response.headers.entries()) {
    if (!EXCLUDED_RESPONSE_HEADERS.has(key.toLowerCase())) {
      responseHeaders.set(key, value);
    }
  }

  // Any other redirect that points inside the origin site is rewritten to the
  // same page on the public site, so the visitor stays on this domain.
  const redirectLocation = response.headers.get("location");
  if (isRedirect(response.status) && redirectLocation) {
    const destination = new URL(redirectLocation, currentUrl);
    if (isOriginUrl(destination)) {
      responseHeaders.set(
        "location",
        toPublicLocation(destination, request.nextUrl.basePath)
      );
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const PATCH = proxyRequest;
export const DELETE = proxyRequest;
export const HEAD = proxyRequest;
export const OPTIONS = proxyRequest;