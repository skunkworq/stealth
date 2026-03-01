import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Only use static export for production builds, allow rewrites in dev
  output: process.env.NODE_ENV === 'production' ? "export" : undefined,
  // Disable image optimization for static export
  images: {
    unoptimized: true,
  },
  // In dev mode, proxy API calls to Go backend
  async rewrites() {
    return [
      {
        source: "/capture/:path*",
        destination: "http://localhost:8080/capture/:path*",
      },
      {
        source: "/baseline/:path*",
        destination: "http://localhost:8080/baseline/:path*",
      },
      {
        source: "/compare",
        destination: "http://localhost:8080/compare",
      },
      {
        source: "/health",
        destination: "http://localhost:8080/health",
      },
      {
        source: "/captures",
        destination: "http://localhost:8080/captures",
      },
      {
        source: "/api/:path*",
        destination: "http://localhost:8080/api/:path*",
      },
    ];
  },
};

export default nextConfig;
