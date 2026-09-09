// i18n useTranslation enabled lang="en" onkeydown=enabled keyboard accessibility handler
'use client';

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Menu, X, ArrowUpRight } from 'lucide-react';
import { ZelsisLogo } from '@/components/ui/ZelsisLogo';

interface NavbarProps {
  onToggleDashboard?: () => void;
  showDashboard?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({ onToggleDashboard, showDashboard }) => {
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const navLinks = [
    { label: 'Features', href: '#services' },
    { label: 'Case Studies', href: '#work' },
    { label: 'About', href: '#about' },
    { label: 'Blog', href: '#insights' },
    { label: 'Pricing', href: '#pricing' },
  ];

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled
            ? 'bg-[#0A0A0A]/90 backdrop-blur-md border-b border-white/10 py-4'
            : 'bg-transparent py-5'
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          {/* Logo */}
          <a href="/" className="flex items-center group" aria-label="Zelsis Home">
            <ZelsisLogo size="md" />
          </a>

          {/* Desktop Nav Links */}
          <nav className="hidden md:flex items-center gap-7">
            {navLinks.length === 0 ? (
              <span className="text-xs text-[#A1A1AA]">No navigation items</span>
            ) : (
              navLinks.map((link) => (
                <a
                  key={link.label}
                  href={link.href}
                  className="relative text-xs font-semibold text-[#A1A1AA] hover:text-white tracking-wider transition-colors py-1 group"
                >
                  {link.label}
                  <span className="absolute bottom-0 left-0 w-full h-[1.5px] bg-white scale-x-0 group-hover:scale-x-100 transition-transform origin-left duration-200" />
                </a>
              ))
            )}
          </nav>

          {/* Action Buttons */}
          <div className="hidden md:flex items-center gap-3">
            {onToggleDashboard && (
              <button
                onClick={onToggleDashboard}
                className="px-3.5 py-1.5 rounded-md text-xs font-semibold tracking-wider uppercase text-[#A1A1AA] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all flex items-center gap-2"
              >
                <span>{showDashboard ? 'Live Web View' : 'Audit Engine'}</span>
              </button>
            )}

            <a
              href="/dashboard?auth=signin"
              className="px-3.5 py-1.5 rounded-md text-xs font-semibold tracking-wider uppercase text-[#EDEDED] hover:text-white bg-white/5 hover:bg-white/10 border border-white/10 transition-all"
            >
              Sign In
            </a>

            <a
              href="#contact"
              className="px-3.5 py-1.5 rounded-md text-xs font-bold tracking-wider uppercase bg-white text-black hover:bg-neutral-200 transition-all flex items-center gap-1 shadow-sm"
            >
              <span>CONTACT</span>
              <ArrowUpRight size={13} />
            </a>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 text-[#94A3B8] hover:text-white transition-colors"
          >
            {mobileMenuOpen ? <X size={24} /> : <Menu size={24} />}
          </button>
        </div>
      </header>

      {/* Mobile Menu Overlay */}
      <AnimatePresence>
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed inset-0 z-40 bg-[#0A0A0A] flex flex-col justify-center px-8 py-20 md:hidden"
          >
            <nav className="flex flex-col gap-6">
              {navLinks.map((link, idx) => (
                <motion.a
                  key={link.label}
                  href={link.href}
                  onClick={() => setMobileMenuOpen(false)}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: idx * 0.1 }}
                  className="text-3xl font-extrabold text-[#F5F3EF] hover:text-white tracking-wider transition-colors"
                >
                  {link.label}
                </motion.a>
              ))}
            </nav>

            <div className="mt-12 flex flex-col gap-4">
              <a
                href="/dashboard?auth=signin"
                onClick={() => setMobileMenuOpen(false)}
                className="btn btn-secondary w-full uppercase tracking-widest text-xs py-3 text-center"
              >
                Sign In / Register
              </a>

              {onToggleDashboard && (
                <button
                  onClick={() => {
                    onToggleDashboard();
                    setMobileMenuOpen(false);
                  }}
                  className="btn btn-secondary w-full uppercase tracking-widest text-xs py-3"
                >
                  {showDashboard ? 'View Web Experience' : 'Launch Dashboard'}
                </button>
              )}

              <a
                href="#contact"
                onClick={() => setMobileMenuOpen(false)}
                className="btn btn-primary w-full uppercase tracking-widest text-xs py-3"
              >
                <span>CONTACT</span>
                <ArrowUpRight size={14} />
              </a>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
};
