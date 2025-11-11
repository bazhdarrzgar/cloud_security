'use client';

import { useEffect, useRef, useState } from 'react';
import { 
  Grid3x3, ArrowUpDown, RotateCw, Plus, Settings, Palette, 
  ChevronRight, Folder, FileText, Link
} from 'lucide-react';

export default function WindowContextMenu({ x, y, items, onClose }) {
  const menuRef = useRef(null);
  const [activeSubmenu, setActiveSubmenu] = useState(null);

  useEffect(() => {
    const handleClickOutside = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [onClose]);

  const getIcon = (iconName) => {
    const icons = {
      'grid': <Grid3x3 className="h-4 w-4" />,
      'sort': <ArrowUpDown className="h-4 w-4" />,
      'refresh': <RotateCw className="h-4 w-4" />,
      'plus': <Plus className="h-4 w-4" />,
      'settings': <Settings className="h-4 w-4" />,
      'palette': <Palette className="h-4 w-4" />,
      'folder': <Folder className="h-4 w-4" />,
      'file': <FileText className="h-4 w-4" />,
      'link': <Link className="h-4 w-4" />,
    };
    return icons[iconName] || null;
  };

  const renderMenuItem = (item, index) => {
    if (item.type === 'separator') {
      return <div key={index} className="h-px bg-slate-700 my-1" />;
    }

    return (
      <div 
        key={index}
        className="relative"
        onMouseEnter={() => item.submenu && setActiveSubmenu(index)}
        onMouseLeave={() => item.submenu && setActiveSubmenu(null)}
      >
        <button
          className="w-full flex items-center justify-between px-3 py-2 text-sm text-white hover:bg-blue-600 transition-colors group"
          onClick={() => {
            if (item.action) {
              item.action();
              onClose();
            }
          }}
        >
          <div className="flex items-center gap-3">
            {item.icon && (
              <span className="text-slate-400 group-hover:text-white">
                {getIcon(item.icon)}
              </span>
            )}
            <span>{item.label}</span>
          </div>
          {item.submenu && (
            <ChevronRight className="h-4 w-4 text-slate-400 group-hover:text-white" />
          )}
        </button>
        
        {/* Submenu */}
        {item.submenu && activeSubmenu === index && (
          <div
            className="absolute left-full top-0 ml-1 bg-slate-800/95 backdrop-blur-xl rounded-lg shadow-2xl border border-slate-700 py-1 min-w-[200px] z-[10003] animate-in fade-in-0 zoom-in-95 duration-100"
          >
            {item.submenu.map((subItem, subIndex) => (
              <button
                key={subIndex}
                className="w-full flex items-center gap-3 px-3 py-2 text-sm text-white hover:bg-blue-600 transition-colors"
                onClick={() => {
                  if (subItem.action) {
                    subItem.action();
                    onClose();
                  }
                }}
              >
                {subItem.icon && (
                  <span className="text-slate-400">
                    {getIcon(subItem.icon)}
                  </span>
                )}
                <span>{subItem.label}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div
      ref={menuRef}
      className="fixed bg-slate-800/95 backdrop-blur-xl rounded-lg shadow-2xl border border-slate-700 py-1 min-w-[220px] z-[10002] animate-in fade-in-0 zoom-in-95 duration-100"
      style={{ left: x, top: y }}
    >
      {items.map((item, index) => renderMenuItem(item, index))}
    </div>
  );
}
