// What to tell the person when the Recognize SDK reports an error. The SDK reports a code (see its
// "Error handling" reference); anything not listed here gets a generic line, and the code goes to the console.

const MESSAGES: Record<string, string> = {
  MEDIA_DEVICES_NO_VIDEO_INPUTS: "No camera was found on this device. Connect one and try again.",
  MEDIA_DEVICES_EMPTY_VIDEO_INPUT_LABEL: "Camera access is blocked. Allow the camera for this site in your browser, then try again.",
  MEDIA_STREAM_NOT_ALLOWED: "Camera access is blocked. Allow the camera for this site in your browser, then try again.",
  MEDIA_STREAM_NOT_FOUND: "No camera was found on this device. Connect one and try again.",
  MEDIA_STREAM_NOT_READABLE: "The camera is in use by another app or tab. Close it and try again.",
  SESSION_MEDIA_STREAM_TIMEOUT: "We couldn't get a clear view of your face in time. Face the camera in good light and try again.",
  SERVER_RECOGNITION_FAILED: "We couldn't verify your face. Try again.",
  SERVER_USER_LOCKED_OUT: "Too many unsuccessful face scans. Wait about ten minutes, then try again.",
  USER_LOCKED_OUT: "Too many unsuccessful face scans. Wait about ten minutes, then try again.",
  SERVER_FORBIDDEN: "The face check refused this sign-in. Start over and try again.",
};

const GENERIC = "The face check didn't complete. Try again.";

export function recognizeErrorMessage(code: string): string {
  return MESSAGES[code] ?? GENERIC;
}

// The Web SDK's components report an error as an event whose `message` holds the code; read it defensively,
// since a custom event may carry it in `detail` instead.
export function recognizeErrorCode(event: Event): string {
  const e = event as Event & { message?: unknown; detail?: unknown };
  if (typeof e.message === "string" && e.message) return e.message;
  if (typeof e.detail === "string" && e.detail) return e.detail;
  const detail = e.detail as { message?: unknown; code?: unknown } | null | undefined;
  if (typeof detail?.code === "string") return detail.code;
  if (typeof detail?.message === "string") return detail.message;
  return "UNKNOWN";
}
