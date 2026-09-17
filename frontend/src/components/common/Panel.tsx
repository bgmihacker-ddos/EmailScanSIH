import React from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

interface PanelProps {
  title: string;
  open?: boolean;
  onToggle?: () => void;
  children: React.ReactNode;
  className?: string;
}

export function Panel({ title, open = true, onToggle, children, className = '' }: PanelProps) {
  return (
    <section className={`soc-panel p-5 ${className}`}>
      <button
        onClick={onToggle}
        className="soc-label flex w-full items-center gap-2 text-left disabled:cursor-default"
        disabled={!onToggle}
      >
        {onToggle && (open ? <ChevronDown size={14} /> : <ChevronRight size={14} />)}
        {title}
      </button>
      {open && <div className="mt-4">{children}</div>}
    </section>
  );
}
