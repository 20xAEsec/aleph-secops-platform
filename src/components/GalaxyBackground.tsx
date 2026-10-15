"use client";

import { useEffect, useRef } from "react";

/*
  GetLayers background "violet-galaxy-beams" (see getlayers.json): 4K master + 2K poster served
  from public/. Contract: motion and composition are fixed; we only tint it with an overlay.
  The scene scrim on top keeps the sidebar side and the edges legible.
*/
export default function GalaxyBackground() {
  const videoRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;
    // Reduced motion: hold on the poster frame instead of playing.
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const apply = () => {
      if (mq.matches) video.pause();
      else video.play().catch(() => {});
    };
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-bg">
      <video
        ref={videoRef}
        className="galaxy-fade h-full w-full object-cover"
        src="/backgrounds/violet-galaxy-beams.mp4"
        poster="/backgrounds/violet-galaxy-beams.webp"
        muted
        loop
        playsInline
        autoPlay
        preload="auto"
      />
      {/* Light tint toward the Ascend navy; kept thin so the footage stays crisp. */}
      <div className="absolute inset-0 bg-[rgba(4,6,15,0.12)]" />
      <div className="scene-scrim" />
    </div>
  );
}
