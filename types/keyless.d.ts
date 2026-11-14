// The PingOne Recognize (Keyless) Web SDK is installed from Ping's Cloudsmith repository (see .npmrc).
// This shim only keeps the build working if the packages ship no types; delete it if they do.
declare module "@keyless/sdk-web-components";
declare module "@keyless/sdk-web";
