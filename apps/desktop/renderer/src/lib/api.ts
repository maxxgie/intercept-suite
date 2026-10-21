let base = "";

export function setApiBase(url: string): void {
  base = url.replace(/\/$/, "");
}

export function apiBase(): string {
  return base;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/**
 * All daemon calls travel through the Electron main process over IPC, so the
 * renderer never makes cross origin requests and the daemon can keep its CORS
 * policy closed.
 */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  if (!base) {
    throw new ApiError("the daemon is not reachable yet", 0);
  }
  try {
    return (await window.intercept.request(method, path, body)) as T;
  } catch (error) {
    throw new ApiError((error as Error).message || "request failed", 0);
  }
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
  text: (path: string) => window.intercept.text(path),
};
