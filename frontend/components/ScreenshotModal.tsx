"use client";

import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";

interface ScreenshotModalProps {
  url: string;
  host: string;
  open: boolean;
  onClose: () => void;
}

export function ScreenshotModal({ url, host, open, onClose }: ScreenshotModalProps) {
  return (
    <Dialog open={open} onOpenChange={(isOpen) => { if (!isOpen) onClose(); }}>
      <DialogContent className="max-w-4xl">
        <DialogHeader>
          <DialogTitle className="font-mono text-sm">{host}</DialogTitle>
        </DialogHeader>
        <div className="flex items-center justify-center overflow-hidden rounded-md bg-muted/30 p-2">
          <img
            src={url}
            alt={`Screenshot of ${host}`}
            className="max-w-full max-h-[70vh] object-contain"
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}
