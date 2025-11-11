'use client';

import { useState, useRef, useEffect } from 'react';
import { X, Minimize2, Maximize2, Minus } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function WindowApp({ 
  window: windowData, 
  isActive, 
  onClose, 
  onMinimize, 
  onMaximize, 
  onFocus, 
  onUpdate,
  zIndex,
  children 
}) {
  const [isDragging, setIsDragging] = useState(false);
  const [isResizing, setIsResizing] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [resizeStart, setResizeStart] = useState({ x: 0, y: 0, width: 0, height: 0 });
  const windowRef = useRef(null);

  const handleMouseDown = (e) => {
    if (e.target.classList.contains('window-titlebar')) {
      setIsDragging(true);
      setDragOffset({
        x: e.clientX - windowData.x,
        y: e.clientY - windowData.y
      });
      onFocus();
    }
  };

  const handleMouseMove = (e) => {
    if (isDragging && !windowData.maximized) {
      onUpdate({
        x: e.clientX - dragOffset.x,
        y: e.clientY - dragOffset.y
      });
    } else if (isResizing) {
      const deltaX = e.clientX - resizeStart.x;
      const deltaY = e.clientY - resizeStart.y;
      
      onUpdate({
        width: Math.max(400, resizeStart.width + deltaX),
        height: Math.max(300, resizeStart.height + deltaY)
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
    setIsResizing(false);
  };

  useEffect(() => {
    if (isDragging || isResizing) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
      
      return () => {
        window.removeEventListener('mousemove', handleMouseMove);
        window.removeEventListener('mouseup', handleMouseUp);
      };
    }
  }, [isDragging, isResizing, dragOffset, resizeStart]);

  const handleResizeStart = (e) => {
    e.stopPropagation();
    setIsResizing(true);
    setResizeStart({
      x: e.clientX,
      y: e.clientY,
      width: windowData.width,
      height: windowData.height
    });
    onFocus();
  };

  const handleTitlebarDoubleClick = () => {
    onMaximize();
  };

  const windowStyle = windowData.maximized ? {
    left: 0,
    top: 0,
    width: '100%',
    height: 'calc(100% - 48px)', // Account for taskbar
  } : {
    left: windowData.x,
    top: windowData.y,
    width: windowData.width,
    height: windowData.height,
  };

  return (
    <div
      ref={windowRef}
      className={`absolute bg-white dark:bg-slate-900 rounded-lg shadow-2xl overflow-hidden flex flex-col border ${
        isActive ? 'border-blue-500' : 'border-slate-300 dark:border-slate-700'
      } transition-all duration-200`}
      style={{ ...windowStyle, zIndex }}
      onClick={onFocus}
    >
      {/* Title Bar */}
      <div
        className="window-titlebar h-10 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center justify-between px-4 cursor-move select-none"
        onMouseDown={handleMouseDown}
        onDoubleClick={handleTitlebarDoubleClick}
      >
        <div className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-200">
          {windowData.title}
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 hover:bg-slate-100 dark:hover:bg-slate-800 rounded"
            onClick={(e) => {
              e.stopPropagation();
              onMinimize();
            }}
          >
            <Minus className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 hover:bg-slate-100 dark:hover:bg-slate-800 rounded"
            onClick={(e) => {
              e.stopPropagation();
              onMaximize();
            }}
          >
            <Maximize2 className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8 w-8 p-0 hover:bg-red-500 hover:text-white rounded transition-colors"
            onClick={(e) => {
              e.stopPropagation();
              onClose();
            }}
          >
            <X className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto bg-white dark:bg-slate-900">
        {children}
      </div>

      {/* Resize Handle */}
      {!windowData.maximized && (
        <div
          className="absolute bottom-0 right-0 w-4 h-4 cursor-se-resize"
          onMouseDown={handleResizeStart}
          style={{
            background: 'linear-gradient(135deg, transparent 50%, rgba(100, 116, 139, 0.3) 50%)'
          }}
        />
      )}
    </div>
  );
}
