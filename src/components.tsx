import React, { useEffect, useRef } from "react";
import { X } from "lucide-react";
export function Badge({ status }: { status: string }) {
  return (
    <span className={`badge ${status.toLowerCase().replaceAll(" ", "-")}`}>
      <span />
      {status}
    </span>
  );
}
export function Dialog({
  title,
  children,
  onClose,
  wide = false,
  notice,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  wide?: boolean;
  notice?: { text: string; error: boolean } | null;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    ref.current?.showModal();
    return () => ref.current?.close();
  }, []);
  return (
    <dialog
      aria-label={title}
      ref={ref}
      className={wide ? "wide" : ""}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="dialog-head">
        <h2>{title}</h2>
        <button
          className="icon-button"
          onClick={onClose}
          aria-label="Close dialog"
        >
          <X size={20} />
        </button>
      </div>
      {notice?.error && (
        <div className="dialog-error" role="alert">
          {notice.text}
        </div>
      )}
      {children}
    </dialog>
  );
}
