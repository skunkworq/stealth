"use client";

import React from "react";

interface CaptchaImageProps {
  src: string;
  alt: string;
  className?: string;
  onClick?: () => void;
}

/**
 * CaptchaImage component for displaying base64-encoded CAPTCHA images.
 *
 * Note: Using standard img tag instead of Next.js Image because:
 * 1. Images are base64 data URIs from API
 * 2. Images are dynamic and can't be optimized at build time
 * 3. Images are small UI elements, not content images
 */
export function CaptchaImage({ src, alt, className, onClick }: CaptchaImageProps) {
  return (
    // eslint-disable-next-line @next/next/no-img-element
    <img src={`data:image/png;base64,${src}`} alt={alt} className={className} onClick={onClick} />
  );
}
