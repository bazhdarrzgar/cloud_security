'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Save, FileText, Type } from 'lucide-react';

export default function Notepad({ initialContent = '', fileName = 'Untitled' }) {
  const [content, setContent] = useState(initialContent);
  const [saved, setSaved] = useState(true);

  const handleContentChange = (e) => {
    setContent(e.target.value);
    setSaved(false);
  };

  const handleSave = () => {
    // Simulate save
    setSaved(true);
    console.log('Saving file:', fileName, content);
  };

  return (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900">
      {/* Menu Bar */}
      <div className="px-4 py-2 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center gap-2">
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          File
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          Edit
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          Format
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          View
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
        >
          Help
        </Button>
        
        <div className="ml-auto flex items-center gap-2">
          {!saved && (
            <span className="text-xs text-amber-600">• Unsaved changes</span>
          )}
          <Button 
            size="sm"
            className="rounded bg-blue-500 hover:bg-blue-600"
            onClick={handleSave}
          >
            <Save className="h-4 w-4 mr-2" />
            Save
          </Button>
        </div>
      </div>

      {/* Toolbar */}
      <div className="px-4 py-2 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700 flex items-center gap-2">
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-200 dark:hover:bg-slate-700"
        >
          <FileText className="h-4 w-4" />
        </Button>
        <Button 
          variant="ghost" 
          size="sm"
          className="h-8 w-8 p-0 rounded hover:bg-slate-200 dark:hover:bg-slate-700"
        >
          <Type className="h-4 w-4" />
        </Button>
        
        <div className="h-4 w-px bg-slate-300 dark:bg-slate-600 mx-2"></div>
        
        <select className="px-2 py-1 text-sm border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-800">
          <option>Consolas</option>
          <option>Arial</option>
          <option>Courier New</option>
          <option>Times New Roman</option>
        </select>
        
        <select className="px-2 py-1 text-sm border border-slate-200 dark:border-slate-700 rounded bg-white dark:bg-slate-800 w-16">
          <option>11</option>
          <option>12</option>
          <option>14</option>
          <option>16</option>
          <option>18</option>
        </select>
      </div>

      {/* Text Area */}
      <div className="flex-1 p-4">
        <textarea
          className="w-full h-full p-4 font-mono text-sm rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
          value={content}
          onChange={handleContentChange}
          placeholder="Start typing..."
          spellCheck="false"
        />
      </div>

      {/* Status Bar */}
      <div className="px-4 py-1 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 flex items-center justify-between text-xs text-slate-600 dark:text-slate-400">
        <div>Ln 1, Col 1</div>
        <div>{content.length} characters</div>
        <div>UTF-8</div>
      </div>
    </div>
  );
}
