import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // The PingOne Recognize Web SDK ships WebAssembly; the bundler has to be able to load .wasm files.
  // (The SDK runs single-threaded by default, so the cross-origin isolation headers that multi-threading
  // needs are not set. See https://docs.pingidentity.com/recognize/web-sdk/web-sdk-reference-multi-threaded.html.)
  webpack(config) {
    config.experiments = { ...config.experiments, asyncWebAssembly: true };
    return config;
  },
};

export default nextConfig;
