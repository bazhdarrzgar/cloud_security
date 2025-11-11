'use client';

import { Monitor, Trash2, Folder, HardDrive, FileText } from 'lucide-react';

export default function WindowDesktop({ icons, onIconDoubleClick, draggedIcon, setDraggedIcon, setDesktopIcons }) {
  
  const handleIconDragStart = (e, icon) => {
    setDraggedIcon(icon);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleIconDragEnd = (e) => {
    setDraggedIcon(null);
  };

  const handleDesktopDrop = (e) => {
    e.preventDefault();
    if (draggedIcon) {
      const rect = e.currentTarget.getBoundingClientRect();
      const x = e.clientX - rect.left - 32; // Center icon
      const y = e.clientY - rect.top - 32;
      
      setDesktopIcons(icons.map(icon => 
        icon.id === draggedIcon.id 
          ? { ...icon, x: Math.max(0, x), y: Math.max(0, y) }
          : icon
      ));
      setDraggedIcon(null);
    }
  };

  const handleDesktopDragOver = (e) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
  };

  const getIconComponent = (iconType) => {
    switch (iconType) {
      case 'pc':
        return <Monitor className="h-12 w-12" />;
      case 'trash':
        return <Trash2 className="h-12 w-12" />;
      case 'folder':
        return <Folder className="h-12 w-12" />;
      case 'drive':
        return <HardDrive className="h-12 w-12" />;
      case 'file':
        return <FileText className="h-12 w-12" />;
      default:
        return <Folder className="h-12 w-12" />;
    }
  };

  return (
    <div 
      className="desktop-area absolute inset-0 pb-12"
      onDrop={handleDesktopDrop}
      onDragOver={handleDesktopDragOver}
    >
      {icons.map(icon => (
        <div
          key={icon.id}
          className="absolute cursor-pointer select-none group"
          style={{ left: icon.x, top: icon.y }}
          draggable
          onDragStart={(e) => handleIconDragStart(e, icon)}
          onDragEnd={handleIconDragEnd}
          onDoubleClick={() => onIconDoubleClick(icon)}
        >
          <div className="flex flex-col items-center p-2 rounded-lg hover:bg-white/20 transition-colors w-24">
            <div className="text-white drop-shadow-lg mb-2">
              {getIconComponent(icon.icon)}
            </div>
            <div className="text-white text-xs font-medium text-center drop-shadow-md bg-blue-600/50 px-2 py-0.5 rounded backdrop-blur-sm">
              {icon.name}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
