'use client';

import React, { createContext, useContext, useState, useCallback } from 'react';
import { ToastMessage, ToastType, ToastContainer } from '@/components/ui/Toast';

interface ToastOptions {
  type?: ToastType;
  title?: string;
  duration?: number;
}

interface ToastContextValue {
  toasts: ToastMessage[];
  toast: {
    (message: string, options?: ToastOptions): string;
    success: (message: string, title?: string, duration?: number) => string;
    error: (message: string, title?: string, duration?: number) => string;
    info: (message: string, title?: string, duration?: number) => string;
  };
  dismiss: (id: string) => void;
  clearAll: () => void;
}

const ToastContext = createContext<ToastContextValue | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setToasts([]);
  }, []);

  const addToast = useCallback(
    (message: string, options?: ToastOptions): string => {
      const id = `toast-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const duration = options?.duration !== undefined ? options.duration : 4000;
      const newToast: ToastMessage = {
        id,
        message,
        type: options?.type || 'info',
        title: options?.title,
        duration,
      };

      setToasts((prev) => [...prev.slice(-4), newToast]); // Keep maximum 5 concurrent toasts

      if (duration > 0) {
        setTimeout(() => {
          dismiss(id);
        }, duration);
      }

      return id;
    },
    [dismiss]
  );

  const toastFn = useCallback(
    (message: string, options?: ToastOptions) => addToast(message, options),
    [addToast]
  ) as ToastContextValue['toast'];

  toastFn.success = useCallback(
    (message: string, title?: string, duration?: number) =>
      addToast(message, { type: 'success', title: title || 'Success', duration }),
    [addToast]
  );

  toastFn.error = useCallback(
    (message: string, title?: string, duration?: number) =>
      addToast(message, { type: 'error', title: title || 'Error', duration: duration || 6000 }),
    [addToast]
  );

  toastFn.info = useCallback(
    (message: string, title?: string, duration?: number) =>
      addToast(message, { type: 'info', title: title || 'Notice', duration }),
    [addToast]
  );

  return (
    <ToastContext.Provider value={{ toasts, toast: toastFn, dismiss, clearAll }}>
      {children}
      <ToastContainer toasts={toasts} onDismiss={dismiss} />
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextValue => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
