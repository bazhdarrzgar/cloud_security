'use client';

import { useState, useEffect, useRef } from 'react';
import { Dialog, DialogContent } from '@/components/ui/dialog';
import WindowDesktop from './windows/WindowDesktop';
import WindowTaskbar from './windows/WindowTaskbar';
import WindowStartMenu from './windows/WindowStartMenu';
import WindowContextMenu from './windows/WindowContextMenu';
import WindowApp from './windows/WindowApp';
import FileExplorer from './windows/apps/FileExplorer';
import Notepad from './windows/apps/Notepad';
import BrowserWindow from './windows/apps/BrowserWindow';

export default function WindowsEnvironment({ isOpen, onClose, onFileSystemChange }) {
  const [currentTime, setCurrentTime] = useState(new Date());
  const [showStartMenu, setShowStartMenu] = useState(false);
  const [contextMenu, setContextMenu] = useState(null);
  const [windows, setWindows] = useState([]);
  const [activeWindowId, setActiveWindowId] = useState(null);
  const [desktopIcons, setDesktopIcons] = useState([
    { id: 'this-pc', name: 'This PC', icon: 'pc', x: 20, y: 20 },
    { id: 'recycle-bin', name: 'Recycle Bin', icon: 'trash', x: 20, y: 120 },
    { id: 'documents', name: 'Documents', icon: 'folder', x: 20, y: 220 },
    { id: 'downloads', name: 'Downloads', icon: 'folder', x: 20, y: 320 },
  ]);
  const [draggedIcon, setDraggedIcon] = useState(null);
  const [fileSystem, setFileSystem] = useState({
    'C:\\': {
      type: 'drive',
      name: 'Local Disk (C:)',
      children: {
        'Users': {
          type: 'folder',
          name: 'Users',
          children: {
            'Admin': {
              type: 'folder',
              name: 'Admin',
              children: {
                'Documents': {
                  type: 'folder',
                  name: 'Documents',
                  children: {
                    'report.txt': {
                      type: 'file',
                      name: 'report.txt',
                      content: 'Security Report\n\nThis is a sample security report document.',
                      size: '2 KB',
                      modified: new Date().toLocaleDateString()
                    },
                    'notes.txt': {
                      type: 'file',
                      name: 'notes.txt',
                      content: 'My Notes\n\nRemember to check the cloud security settings.',
                      size: '1 KB',
                      modified: new Date().toLocaleDateString()
                    }
                  }
                },
                'Desktop': {
                  type: 'folder',
                  name: 'Desktop',
                  children: {}
                },
                'Downloads': {
                  type: 'folder',
                  name: 'Downloads',
                  children: {}
                }
              }
            }
          }
        },
        'Program Files': {
          type: 'folder',
          name: 'Program Files',
          children: {}
        },
        'Windows': {
          type: 'folder',
          name: 'Windows',
          children: {
            'System32': {
              type: 'folder',
              name: 'System32',
              children: {}
            }
          }
        }
      }
    },
    'D:\\': {
      type: 'drive',
      name: 'Data Disk (D:)',
      children: {}
    }
  });

  const windowIdCounter = useRef(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const openApp = (appType, props = {}) => {
    const newWindow = {
      id: ++windowIdCounter.current,
      type: appType,
      title: props.title || appType,
      x: 100 + (windows.length * 30),
      y: 50 + (windows.length * 30),
      width: props.width || 900,
      height: props.height || 600,
      minimized: false,
      maximized: false,
      props
    };
    setWindows([...windows, newWindow]);
    setActiveWindowId(newWindow.id);
  };

  const closeWindow = (id) => {
    setWindows(windows.filter(w => w.id !== id));
    if (activeWindowId === id) {
      const remaining = windows.filter(w => w.id !== id);
      setActiveWindowId(remaining.length > 0 ? remaining[remaining.length - 1].id : null);
    }
  };

  const minimizeWindow = (id) => {
    setWindows(windows.map(w => 
      w.id === id ? { ...w, minimized: true } : w
    ));
  };

  const restoreWindow = (id) => {
    const window = windows.find(w => w.id === id);
    if (window) {
      setWindows(windows.map(w => 
        w.id === id ? { ...w, minimized: false, maximized: false } : w
      ));
      setActiveWindowId(id);
    }
  };

  const maximizeWindow = (id) => {
    setWindows(windows.map(w => 
      w.id === id ? { ...w, maximized: !w.maximized } : w
    ));
  };

  const updateWindow = (id, updates) => {
    setWindows(windows.map(w => 
      w.id === id ? { ...w, ...updates } : w
    ));
  };

  const bringToFront = (id) => {
    setActiveWindowId(id);
  };

  const handleDesktopClick = (e) => {
    if (e.target === e.currentTarget) {
      setShowStartMenu(false);
      setContextMenu(null);
    }
  };

  const createNewFolder = (path = ['C:\\', 'Users', 'Admin', 'Desktop']) => {
    const folderName = prompt('Enter folder name:', 'New Folder');
    if (!folderName) return;

    setFileSystem(prevFS => {
      const newFS = { ...prevFS };
      let current = newFS;
      
      // Navigate to the target path
      for (let i = 0; i < path.length; i++) {
        if (i === path.length - 1) {
          // We're at the target location
          if (!current[path[i]].children) {
            current[path[i]].children = {};
          }
          current[path[i]].children[folderName] = {
            type: 'folder',
            name: folderName,
            children: {}
          };
        } else {
          current = current[path[i]].children || current[path[i]];
        }
      }
      
      if (onFileSystemChange) {
        onFileSystemChange('folder_created', path, folderName);
      }
      
      return newFS;
    });
    
    // If creating on Desktop, add desktop icon
    const pathString = path.join('/');
    if (pathString === 'C:\\/Users/Admin/Desktop') {
      const newIcon = {
        id: `desktop-folder-${Date.now()}`,
        name: folderName,
        icon: 'folder',
        x: 20,
        y: 20 + (desktopIcons.length * 100),
        path: [...path, folderName]
      };
      setDesktopIcons([...desktopIcons, newIcon]);
    }
    
    setContextMenu(null);
  };

  const createNewFile = (path = ['C:\\', 'Users', 'Admin', 'Desktop']) => {
    const fileName = prompt('Enter file name:', 'New File.txt');
    if (!fileName) return;

    setFileSystem(prevFS => {
      const newFS = { ...prevFS };
      let current = newFS;
      
      // Navigate to the target path
      for (let i = 0; i < path.length; i++) {
        if (i === path.length - 1) {
          // We're at the target location
          if (!current[path[i]].children) {
            current[path[i]].children = {};
          }
          current[path[i]].children[fileName] = {
            type: 'file',
            name: fileName,
            content: '',
            size: '0 KB',
            modified: new Date().toLocaleDateString()
          };
        } else {
          current = current[path[i]].children || current[path[i]];
        }
      }
      
      if (onFileSystemChange) {
        onFileSystemChange('file_created', path, fileName);
      }
      
      return newFS;
    });
    
    // If creating on Desktop, add desktop icon
    const pathString = path.join('/');
    if (pathString === 'C:\\/Users/Admin/Desktop') {
      const newIcon = {
        id: `desktop-file-${Date.now()}`,
        name: fileName,
        icon: 'file',
        x: 20,
        y: 20 + (desktopIcons.length * 100),
        path: [...path, fileName],
        isFile: true
      };
      setDesktopIcons([...desktopIcons, newIcon]);
    }
    
    setContextMenu(null);
  };

  const handleDesktopRightClick = (e) => {
    e.preventDefault();
    if (e.target === e.currentTarget || e.target.classList.contains('desktop-area')) {
      const desktopPath = ['C:\\', 'Users', 'Admin', 'Desktop'];
      setContextMenu({
        x: e.clientX,
        y: e.clientY,
        items: [
          { label: 'View', icon: 'grid', submenu: [
            { label: 'Large icons', action: () => console.log('Large icons') },
            { label: 'Medium icons', action: () => console.log('Medium icons') },
            { label: 'Small icons', action: () => console.log('Small icons') },
          ]},
          { label: 'Sort by', icon: 'sort', submenu: [
            { label: 'Name', action: () => console.log('Sort by name') },
            { label: 'Size', action: () => console.log('Sort by size') },
            { label: 'Date modified', action: () => console.log('Sort by date') },
          ]},
          { type: 'separator' },
          { label: 'Refresh', icon: 'refresh', action: () => console.log('Refresh') },
          { type: 'separator' },
          { label: 'New', icon: 'plus', submenu: [
            { label: 'Folder', action: () => createNewFolder(desktopPath) },
            { label: 'Text Document', action: () => createNewFile(desktopPath) },
          ]},
          { type: 'separator' },
          { label: 'Display settings', icon: 'settings', action: () => console.log('Display settings') },
          { label: 'Personalize', icon: 'palette', action: () => console.log('Personalize') },
        ]
      });
    }
  };

  const handleIconDoubleClick = (icon) => {
    // Handle custom desktop icons (folders and files)
    if (icon.path) {
      if (icon.isFile) {
        // Open file in Notepad
        let current = fileSystem;
        for (const segment of icon.path) {
          if (current[segment]) {
            current = current[segment];
          } else if (current.children && current.children[segment]) {
            current = current.children[segment];
          }
        }
        if (current.content !== undefined) {
          openApp('Notepad', { 
            title: icon.name + ' - Notepad',
            content: current.content,
            fileName: icon.name 
          });
        }
      } else {
        // Open folder in File Explorer
        openApp('FileExplorer', { title: icon.name, path: icon.path });
      }
      return;
    }
    
    // Handle default icons
    switch (icon.id) {
      case 'this-pc':
        openApp('FileExplorer', { title: 'This PC', path: ['C:\\'] });
        break;
      case 'recycle-bin':
        openApp('FileExplorer', { title: 'Recycle Bin', path: ['Recycle Bin'] });
        break;
      case 'documents':
        openApp('FileExplorer', { title: 'Documents', path: ['C:\\', 'Users', 'Admin', 'Documents'] });
        break;
      case 'downloads':
        openApp('FileExplorer', { title: 'Downloads', path: ['C:\\', 'Users', 'Admin', 'Downloads'] });
        break;
    }
  };

  const handleStartClick = () => {
    setShowStartMenu(!showStartMenu);
    setContextMenu(null);
  };

  const handleAppLaunch = (appName) => {
    switch (appName) {
      case 'File Explorer':
        openApp('FileExplorer', { title: 'File Explorer', path: ['C:\\'] });
        break;
      case 'Notepad':
        openApp('Notepad', { title: 'Untitled - Notepad' });
        break;
      case 'Browser':
        openApp('BrowserWindow', { title: 'Microsoft Edge', url: 'https://www.example.com' });
        break;
      case 'Settings':
        openApp('FileExplorer', { title: 'Settings', path: ['C:\\'] });
        break;
    }
    setShowStartMenu(false);
  };

  const renderAppContent = (window) => {
    switch (window.type) {
      case 'FileExplorer':
        return (
          <FileExplorer 
            fileSystem={fileSystem}
            setFileSystem={setFileSystem}
            initialPath={window.props.path}
            onClose={() => closeWindow(window.id)}
            onFileSystemChange={onFileSystemChange}
            onOpenFile={(fileName, content) => {
              openApp('Notepad', { 
                title: fileName + ' - Notepad',
                content: content,
                fileName: fileName 
              });
            }}
          />
        );
      case 'Notepad':
        return (
          <Notepad 
            initialContent={window.props.content || ''}
            fileName={window.props.fileName}
          />
        );
      case 'BrowserWindow':
        return (
          <BrowserWindow 
            initialUrl={window.props.url}
          />
        );
      default:
        return <div className="p-4">Unknown application type</div>;
    }
  };

  if (!isOpen) return null;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-[100vw] max-h-[100vh] w-screen h-screen p-0 m-0 overflow-hidden bg-transparent border-0 gap-0">
        <div 
          className="relative w-full h-full"
          style={{
            background: 'linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #60a5fa 100%)',
            backgroundImage: 'url("data:image/svg+xml,%3Csvg width=\'1920\' height=\'1080\' xmlns=\'http://www.w3.org/2000/svg\'%3E%3Cdefs%3E%3ClinearGradient id=\'grad1\' x1=\'0%25\' y1=\'0%25\' x2=\'100%25\' y2=\'100%25\'%3E%3Cstop offset=\'0%25\' style=\'stop-color:%231e3a8a;stop-opacity:1\' /%3E%3Cstop offset=\'50%25\' style=\'stop-color:%233b82f6;stop-opacity:1\' /%3E%3Cstop offset=\'100%25\' style=\'stop-color:%2360a5fa;stop-opacity:1\' /%3E%3C/linearGradient%3E%3Cfilter id=\'blur\'%3E%3CfeGaussianBlur stdDeviation=\'80\' /%3E%3C/filter%3E%3C/defs%3E%3Crect width=\'1920\' height=\'1080\' fill=\'url(%23grad1)\' /%3E%3Cellipse cx=\'300\' cy=\'300\' rx=\'400\' ry=\'300\' fill=\'%2360a5fa\' opacity=\'0.3\' filter=\'url(%23blur)\' /%3E%3Cellipse cx=\'1500\' cy=\'700\' rx=\'500\' ry=\'400\' fill=\'%231e40af\' opacity=\'0.3\' filter=\'url(%23blur)\' /%3E%3C/svg%3E")',
            backgroundSize: 'cover'
          }}
          onClick={handleDesktopClick}
          onContextMenu={handleDesktopRightClick}
        >
          {/* Desktop with Icons */}
          <WindowDesktop 
            icons={desktopIcons}
            onIconDoubleClick={handleIconDoubleClick}
            draggedIcon={draggedIcon}
            setDraggedIcon={setDraggedIcon}
            setDesktopIcons={setDesktopIcons}
          />

          {/* Windows */}
          {windows.map((window, index) => (
            !window.minimized && (
              <WindowApp
                key={window.id}
                window={window}
                isActive={activeWindowId === window.id}
                onClose={() => closeWindow(window.id)}
                onMinimize={() => minimizeWindow(window.id)}
                onMaximize={() => maximizeWindow(window.id)}
                onFocus={() => bringToFront(window.id)}
                onUpdate={(updates) => updateWindow(window.id, updates)}
                zIndex={1000 + (activeWindowId === window.id ? windows.length : index)}
              >
                {renderAppContent(window)}
              </WindowApp>
            )
          ))}

          {/* Taskbar */}
          <WindowTaskbar
            currentTime={currentTime}
            windows={windows}
            activeWindowId={activeWindowId}
            onStartClick={handleStartClick}
            onWindowClick={restoreWindow}
            onAppLaunch={handleAppLaunch}
          />

          {/* Start Menu */}
          {showStartMenu && (
            <WindowStartMenu
              onClose={() => setShowStartMenu(false)}
              onAppLaunch={handleAppLaunch}
            />
          )}

          {/* Context Menu */}
          {contextMenu && (
            <WindowContextMenu
              x={contextMenu.x}
              y={contextMenu.y}
              items={contextMenu.items}
              onClose={() => setContextMenu(null)}
            />
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
