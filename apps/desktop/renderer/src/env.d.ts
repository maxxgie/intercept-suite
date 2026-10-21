/// <reference types="vite/client" />

export interface DaemonEvent {
  type: string;
  ts: number;
  data: Record<string, unknown>;
}

declare global {
  interface Window {
    intercept: {
      info(): Promise<{ apiBase: string; state: string }>;
      request(method: string, path: string, body?: unknown): Promise<unknown>;
      text(path: string): Promise<string>;
      onEvent(callback: (event: DaemonEvent) => void): () => void;
      onStatus(callback: (status: { state: string; code?: number; adopted?: boolean }) => void): () => void;
      openExternal(url: string): void;
    };
  }
}

export {};
