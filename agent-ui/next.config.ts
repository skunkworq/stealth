import type { NextConfig } from "next";

const config: NextConfig = {
  output: "export",
  distDir: "out",
  images: { unoptimized: true },
};

export default config;
