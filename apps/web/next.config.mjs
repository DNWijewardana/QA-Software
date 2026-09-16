/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The web app is a thin presentation layer that proxies to the platform API (BFF pattern).
  // It bundles NO @qa/* packages, so there is nothing to transpile and no Node-only code reaches the client.
};

export default nextConfig;
