// What the browser is told about the face step. The authorization token is meant for the browser
// (it is short-lived and only valid for this username); the signing key stays on the server.

export type RecognizeMode = "enroll" | "auth";

export type RecognizeView = {
  mode: RecognizeMode;
  username: string;
  customer: string;
  serviceUrl: string;
  authorizationToken: string;
  transactionData: string;
};
