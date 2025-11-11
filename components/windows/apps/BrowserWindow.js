'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { 
  ArrowLeft, ArrowRight, RotateCw, Home, Lock, 
  Star, MoreHorizontal, Plus, X, Search
} from 'lucide-react';

export default function BrowserWindow({ initialUrl = 'https://www.example.com' }) {
  const [url, setUrl] = useState(initialUrl);
  const [inputUrl, setInputUrl] = useState(initialUrl);
  const [tabs, setTabs] = useState([
    { id: 1, title: 'New Tab', url: initialUrl, active: true }
  ]);
  const [activeTab, setActiveTab] = useState(1);

  const handleNavigate = () => {
    setUrl(inputUrl);
  };

  const addNewTab = () => {
    const newTab = {
      id: Date.now(),
      title: 'New Tab',
      url: 'https://www.example.com',
      active: false
    };
    setTabs([...tabs, newTab]);
    setActiveTab(newTab.id);
  };

  const closeTab = (tabId, e) => {
    e.stopPropagation();
    const newTabs = tabs.filter(t => t.id !== tabId);
    if (newTabs.length === 0) {
      addNewTab();
    } else {
      setTabs(newTabs);
      if (activeTab === tabId) {
        setActiveTab(newTabs[0].id);
      }
    }
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900">
      {/* Tabs Bar */}
      <div className="bg-slate-100 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700 flex items-center">
        <div className="flex-1 flex items-center overflow-x-auto">
          {tabs.map(tab => (
            <div
              key={tab.id}
              className={`group relative flex items-center gap-2 px-4 py-2 min-w-[200px] max-w-[240px] cursor-pointer border-r border-slate-200 dark:border-slate-700 ${
                activeTab === tab.id 
                  ? 'bg-white dark:bg-slate-900' 
                  : 'hover:bg-slate-50 dark:hover:bg-slate-700/50'
              }`}
              onClick={() => setActiveTab(tab.id)}
            >
              <div className="flex-1 truncate text-sm">{tab.title}</div>
              <button
                className="opacity-0 group-hover:opacity-100 hover:bg-slate-200 dark:hover:bg-slate-600 rounded p-1 transition-opacity"
                onClick={(e) => closeTab(tab.id, e)}
              >
                <X className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 mx-1 rounded hover:bg-slate-200 dark:hover:bg-slate-700"
          onClick={addNewTab}
        >
          <Plus className="h-4 w-4" />
        </Button>
      </div>

      {/* Address Bar */}
      <div className="px-4 py-3 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center gap-2">
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <ArrowLeft className="h-4 w-4" />
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <ArrowRight className="h-4 w-4" />
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <RotateCw className="h-4 w-4" />
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <Home className="h-4 w-4" />
        </Button>
        
        <div className="flex-1 flex items-center gap-2 bg-slate-100 dark:bg-slate-800 rounded-lg px-3 py-2 border border-slate-200 dark:border-slate-700">
          <Lock className="h-4 w-4 text-green-600" />
          <Input 
            type="text" 
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && handleNavigate()}
            className="flex-1 bg-transparent border-none outline-none text-sm focus-visible:ring-0 focus-visible:ring-offset-0"
          />
        </div>

        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <Star className="h-4 w-4" />
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </div>

      {/* Browser Content */}
      <div className="flex-1 bg-white dark:bg-slate-900 flex items-center justify-center">
        <div className="text-center max-w-md p-8">
          <div className="w-24 h-24 bg-gradient-to-br from-blue-400 to-blue-600 rounded-full flex items-center justify-center mx-auto mb-6">
            <Search className="h-12 w-12 text-white" />
          </div>
          <h2 className="text-2xl font-bold mb-3 text-slate-800 dark:text-white">
            Browser Simulation
          </h2>
          <p className="text-slate-600 dark:text-slate-400 mb-4">
            This is a simulated browser window. In a real implementation, this would display web content.
          </p>
          <div className="bg-slate-100 dark:bg-slate-800 rounded-lg p-4 text-left">
            <div className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
              Current URL:
            </div>
            <div className="text-sm text-blue-600 dark:text-blue-400 break-all">
              {url}
            </div>
          </div>
          <div className="mt-6 flex gap-2 justify-center">
            <Button size="sm" variant="outline">
              View Bookmarks
            </Button>
            <Button size="sm" variant="outline">
              History
            </Button>
            <Button size="sm" variant="outline">
              Settings
            </Button>
          </div>
        </div>
      </div>

      {/* Status Bar */}
      <div className="px-4 py-1 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
        <div>Done</div>
        <div>Zoom: 100%</div>
      </div>
    </div>
  );
}
