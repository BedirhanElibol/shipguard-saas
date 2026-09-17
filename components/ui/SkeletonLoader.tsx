import React from 'react';

interface SkeletonProps {
  className?: string;
}

/**
 * Single text line skeleton placeholder.
 */
export function SkeletonText({ className = 'h-3 w-24' }: SkeletonProps) {
  return <div className={`skeleton ${className}`} aria-hidden="true" />;
}

/**
 * Severity badge skeleton matching the standard badge dimensions (min-w-[62px] h-5).
 */
export function SkeletonBadge({ className = 'h-5 w-16' }: SkeletonProps) {
  return <div className={`skeleton rounded ${className}`} aria-hidden="true" />;
}

/**
 * Data table row skeleton with columns matching dense audit findings table.
 */
export function SkeletonRow({ className = '' }: SkeletonProps) {
  return (
    <tr className={`border-b border-white/5 ${className}`} aria-hidden="true">
      <td className="py-3.5 px-4 whitespace-nowrap">
        <SkeletonBadge />
      </td>
      <td className="py-3.5 px-4">
        <SkeletonBadge className="h-5 w-20" />
      </td>
      <td className="py-3.5 px-4">
        <SkeletonText className="h-3.5 w-48 sm:w-64" />
      </td>
      <td className="py-3.5 px-4">
        <SkeletonText className="h-3 w-24" />
      </td>
      <td className="py-3.5 px-4">
        <SkeletonText className="h-3 w-32" />
      </td>
      <td className="py-3.5 px-4">
        <SkeletonBadge className="h-4 w-14" />
      </td>
      <td className="py-3.5 px-4 text-right">
        <div className="skeleton h-6 w-20 rounded ml-auto" />
      </td>
    </tr>
  );
}

/**
 * Card skeleton placeholder for mobile findings or dashboard panels.
 */
export function SkeletonCard({ className = '' }: SkeletonProps) {
  return (
    <div
      className={`p-4 rounded-xl bg-[#0A0A0A] border border-white/10 flex flex-col gap-3 ${className}`}
      aria-hidden="true"
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <SkeletonBadge />
          <SkeletonBadge className="h-5 w-20" />
        </div>
        <SkeletonBadge className="h-4 w-12" />
      </div>
      <SkeletonText className="h-4 w-3/4" />
      <SkeletonText className="h-3 w-1/2" />
      <div className="pt-2 border-t border-white/5 flex items-center justify-between">
        <SkeletonText className="h-3 w-20" />
        <div className="skeleton h-6 w-16 rounded" />
      </div>
    </div>
  );
}
