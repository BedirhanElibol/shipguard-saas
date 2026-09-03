'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';

interface PageTransitionProps {
  children: React.ReactNode;
  routeKey?: string;
}

export const PageTransition: React.FC<PageTransitionProps> = ({ children, routeKey }) => {
  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={routeKey}
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -12 }}
        transition={{
          duration: 0.25,
          ease: 'easeInOut'
        }}
        className="w-full h-full"
        suppressHydrationWarning
      >
        {children}
      </motion.div>
    </AnimatePresence>
  );
};
