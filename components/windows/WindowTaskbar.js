'use client';

import { Search, Wifi, Volume2, Battery, ChevronUp } from 'lucide-react';
import { Button } from '@/components/ui/button';

export default function WindowTaskbar({ currentTime, windows, activeWindowId, onStartClick, onWindowClick, onAppLaunch }) {
  
  const formatTime = (date) => {
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (date) => {
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  return (
    <div className="absolute bottom-0 left-0 right-0 h-12 bg-slate-900/90 backdrop-blur-xl border-t border-slate-700/50 flex items-center px-1 z-[10000]">
      {/* Start Button */}
      <Button
        variant="ghost"
        size="sm"
        className="h-10 w-10 p-0 hover:bg-slate-700/50 rounded-lg transition-colors"
        onClick={onStartClick}
      >
        <svg className="w-5 h-5 text-white" viewBox="0 0 24 24" fill="currentColor">
          <path d="M3 3h8v8H3V3zm10 0h8v8h-8V3zM3 13h8v8H3v-8zm10 0h8v8h-8v-8z"/>
        </svg>
      </Button>

      {/* Search Bar */}
      <div className="ml-2 flex items-center bg-slate-800/50 rounded-lg px-3 py-1.5 w-64 hover:bg-slate-700/50 transition-colors">
        <Search className="h-4 w-4 text-slate-400 mr-2" />
        <input 
          type="text" 
          placeholder="Search" 
          className="bg-transparent border-none outline-none text-sm text-white placeholder-slate-400 w-full"
        />
      </div>

      {/* Open Windows */}
      <div className="flex items-center gap-1 ml-2">
        {windows.map(window => (
          <Button
            key={window.id}
            variant="ghost"
            size="sm"
            className={`h-10 px-3 rounded-lg transition-colors ${
              activeWindowId === window.id 
                ? 'bg-slate-700 hover:bg-slate-600' 
                : 'hover:bg-slate-700/50'
            }`}
            onClick={() => onWindowClick(window.id)}
          >
            <span className="text-white text-xs truncate max-w-[150px]">
              {window.title}
            </span>
          </Button>
        ))}
      </div>

      {/* System Tray */}
      <div className="ml-auto flex items-center gap-2">
        <Button variant="ghost" size="sm" className="h-10 w-10 p-0 hover:bg-slate-700/50 rounded-lg">
          <ChevronUp className="h-4 w-4 text-white" />
        </Button>
        
        <div className="flex items-center gap-3 px-3">
          <Wifi className="h-4 w-4 text-white" />
          <Volume2 className="h-4 w-4 text-white" />
          <Battery className="h-4 w-4 text-white" />
        </div>

        {/* Clock */}
        <div className="px-3 py-1 hover:bg-slate-700/50 rounded-lg transition-colors cursor-pointer">
          <div className="text-white text-xs font-medium">
            {formatTime(currentTime)}
          </div>
          <div className="text-white text-xs">
            {formatDate(currentTime)}
          </div>
        </div>
      </div>
    </div>
  );
}
