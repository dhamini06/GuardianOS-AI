/**
 * WebSocket subscription to /api/ws.
 *
 * The server pushes one frame per tick: `{ seq, items: [{kind:"report"|"health", data}] }`.
 * Auth token travels as a query parameter (`?token=`), matching the backend.
 * Auto-reconnects with a short backoff; re-subscribes on token change.
 */

import { useEffect } from "react";
import type { WsFrame } from "./types";
import { getToken } from "./client";

export function useGuardianSocket(
  onFrame: (frame: WsFrame) => void,
  onStatus: (connected: boolean) => void,
): void {
  useEffect(() => {
    let ws: WebSocket | null = null;
    let retries = 0;
    let closed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (closed) {
        return;
      }
      const token = getToken();
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const url = `${protocol}//${window.location.host}/api/ws${
        token ? `?token=${encodeURIComponent(token)}` : ""
      }`;

      try {
        ws = new WebSocket(url);
      } catch {
        onStatus(false);
        retries += 1;
        reconnectTimer = setTimeout(connect, Math.min(1000 * 2 ** retries, 15000));
        return;
      }

      ws.onopen = () => {
        retries = 0;
        onStatus(true);
      };
      ws.onmessage = (event: MessageEvent<string>) => {
        try {
          const frame = JSON.parse(event.data) as WsFrame;
          onFrame(frame);
        } catch {
          // ignore malformed frames
        }
      };
      ws.onclose = () => {
        onStatus(false);
        if (!closed) {
          retries += 1;
          reconnectTimer = setTimeout(connect, Math.min(1000 * 2 ** retries, 15000));
        }
      };
      ws.onerror = () => {
        ws?.close();
      };
    };

    connect();

    return () => {
      closed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      ws?.close();
    };
    // Re-subscribe when the token changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [getToken()]);
}
