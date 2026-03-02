"use client";

import { useState, useCallback } from "react";

interface Toast {
  id: string;
  title: string;
  description: string;
  visible: boolean;
}

let toastId = 0;

export function useToasts() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((title: string, description: string) => {
    const id = `toast-${++toastId}`;
    const toast: Toast = { id, title, description, visible: true };

    setToasts(prev => [...prev, toast]);

    const FADE_DURATION = 300;
    const DISPLAY_DURATION = 3000;

    // Fade out after display duration
    setTimeout(() => {
      setToasts(prev => prev.map(t => (t.id === id ? { ...t, visible: false } : t)));
      // Remove after fade animation
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, FADE_DURATION);
    }, DISPLAY_DURATION);
  }, []);

  return { toasts, addToast };
}

export function ToastContainer({ toasts }: { toasts: Toast[] }) {
  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      className="fixed top-4 right-4 z-[10000] flex flex-col gap-2 pointer-events-none"
    >
      {toasts.map(toast => (
        <div
          key={toast.id}
          className={`
            pointer-events-auto skeuo-raised rounded-lg px-4 py-3 max-w-sm
            transition-all duration-300
            ${toast.visible ? "translate-x-0 opacity-100" : "translate-x-[100%] opacity-0"}
          `}
          style={{
            animation: toast.visible ? "slideInRight 0.3s ease" : undefined,
          }}
        >
          <div className="flex items-center gap-2 mb-0.5">
            <span className="led-green" aria-hidden="true" />
            <span className="text-sm font-semibold text-foreground">{toast.title}</span>
          </div>
          <p className="text-xs text-muted-foreground font-mono ml-[18px]">{toast.description}</p>
        </div>
      ))}
      <style jsx global>{`
        @keyframes slideInRight {
          from {
            transform: translateX(100%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
      `}</style>
    </div>
  );
}
