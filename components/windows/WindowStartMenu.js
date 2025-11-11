'use client';

import { 
  Folder, FileText, Globe, Settings, Power, User, 
  Search, Grid3x3, Calculator, Image, Music, Film,
  Mail, Calendar, Clock, Download
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export default function WindowStartMenu({ onClose, onAppLaunch }) {
  
  const apps = [
    { name: 'File Explorer', icon: <Folder className="h-6 w-6" />, color: 'bg-yellow-500' },
    { name: 'Notepad', icon: <FileText className="h-6 w-6" />, color: 'bg-blue-500' },
    { name: 'Browser', icon: <Globe className="h-6 w-6" />, color: 'bg-cyan-500' },
    { name: 'Settings', icon: <Settings className="h-6 w-6" />, color: 'bg-gray-500' },
    { name: 'Calculator', icon: <Calculator className="h-6 w-6" />, color: 'bg-indigo-500' },
    { name: 'Photos', icon: <Image className="h-6 w-6" />, color: 'bg-purple-500' },
    { name: 'Music', icon: <Music className="h-6 w-6" />, color: 'bg-pink-500' },
    { name: 'Videos', icon: <Film className="h-6 w-6" />, color: 'bg-red-500' },
    { name: 'Mail', icon: <Mail className="h-6 w-6" />, color: 'bg-blue-600' },
    { name: 'Calendar', icon: <Calendar className="h-6 w-6" />, color: 'bg-green-500' },
    { name: 'Clock', icon: <Clock className="h-6 w-6" />, color: 'bg-orange-500' },
    { name: 'Downloads', icon: <Download className="h-6 w-6" />, color: 'bg-teal-500' },
  ];

  return (
    <div className="absolute bottom-14 left-2 w-[640px] h-[700px] bg-slate-900/95 backdrop-blur-xl rounded-xl shadow-2xl border border-slate-700/50 overflow-hidden z-[10001] animate-in slide-in-from-bottom-4 duration-200">
      {/* Search Box */}
      <div className="p-6 pb-4">
        <div className="flex items-center bg-slate-800 rounded-lg px-4 py-3 border border-slate-700">
          <Search className="h-5 w-5 text-slate-400 mr-3" />
          <Input 
            type="text" 
            placeholder="Search for apps, settings, and documents" 
            className="bg-transparent border-none outline-none text-white placeholder-slate-400 flex-1 focus-visible:ring-0 focus-visible:ring-offset-0"
          />
        </div>
      </div>

      {/* Pinned Apps */}
      <div className="px-6 pb-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-white font-semibold text-sm">Pinned</h3>
          <Button variant="ghost" size="sm" className="text-xs text-slate-400 hover:text-white">
            All apps
          </Button>
        </div>
        
        <div className="grid grid-cols-6 gap-3">
          {apps.map((app, index) => (
            <button
              key={index}
              className="flex flex-col items-center p-3 rounded-lg hover:bg-slate-800 transition-colors group"
              onClick={() => onAppLaunch(app.name)}
            >
              <div className={`${app.color} w-12 h-12 rounded-lg flex items-center justify-center mb-2 text-white group-hover:scale-110 transition-transform`}>
                {app.icon}
              </div>
              <span className="text-white text-xs text-center truncate w-full">
                {app.name}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Recommended */}
      <div className="px-6 pb-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-white font-semibold text-sm">Recommended</h3>
          <Button variant="ghost" size="sm" className="text-xs text-slate-400 hover:text-white">
            More
          </Button>
        </div>
        
        <div className="space-y-2">
          {[
            { name: 'report.txt', icon: <FileText className="h-5 w-5" />, desc: '2 hours ago' },
            { name: 'Documents', icon: <Folder className="h-5 w-5" />, desc: 'Yesterday' },
            { name: 'Downloads', icon: <Download className="h-5 w-5" />, desc: '3 days ago' },
          ].map((item, index) => (
            <button
              key={index}
              className="w-full flex items-center gap-3 p-2 rounded-lg hover:bg-slate-800 transition-colors"
            >
              <div className="bg-slate-800 w-10 h-10 rounded flex items-center justify-center text-blue-400">
                {item.icon}
              </div>
              <div className="flex-1 text-left">
                <div className="text-white text-sm">{item.name}</div>
                <div className="text-slate-400 text-xs">{item.desc}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div className="absolute bottom-0 left-0 right-0 h-16 bg-slate-800/50 backdrop-blur-sm border-t border-slate-700/50 flex items-center justify-between px-6">
        <div className="flex items-center gap-3">
          <Button variant="ghost" size="sm" className="flex items-center gap-2 text-white hover:bg-slate-700">
            <div className="w-8 h-8 bg-blue-500 rounded-full flex items-center justify-center">
              <User className="h-5 w-5" />
            </div>
            <span className="text-sm">Admin</span>
          </Button>
        </div>
        
        <Button 
          variant="ghost" 
          size="sm" 
          className="flex items-center gap-2 text-white hover:bg-slate-700 rounded-lg px-4 py-2"
        >
          <Power className="h-5 w-5" />
        </Button>
      </div>
    </div>
  );
}
