'use client';

import { useState, useEffect } from 'react';
import { 
  ArrowLeft, Home, ChevronRight, Search, MoreHorizontal,
  HardDrive, Folder, File, Trash2, Plus, Grid3x3,
  FolderOpen, FilePlus, FolderPlus, Edit, Copy, Scissors
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

export default function FileExplorer({ fileSystem, setFileSystem, initialPath, onClose, onOpenFile, onFileSystemChange }) {
  const [currentPath, setCurrentPath] = useState(initialPath || ['C:\\']);
  const [selectedItem, setSelectedItem] = useState(null);
  const [viewMode, setViewMode] = useState('grid'); // 'grid' or 'list'
  const [showNewDialog, setShowNewDialog] = useState(false);
  const [newItemType, setNewItemType] = useState('folder'); // 'folder' or 'file'
  const [newItemName, setNewItemName] = useState('');
  const [showRenameDialog, setShowRenameDialog] = useState(false);
  const [renameValue, setRenameValue] = useState('');
  const [clipboard, setClipboard] = useState(null); // {type: 'copy'|'cut', path: [], itemName: ''}
  const [contextMenu, setContextMenu] = useState(null); // {x, y, type}

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ctrl+C - Copy
      if (e.ctrlKey && e.key === 'c' && selectedItem) {
        e.preventDefault();
        handleCopy();
      }
      // Ctrl+X - Cut
      if (e.ctrlKey && e.key === 'x' && selectedItem) {
        e.preventDefault();
        handleCut();
      }
      // Ctrl+V - Paste
      if (e.ctrlKey && e.key === 'v' && clipboard) {
        e.preventDefault();
        handlePaste();
      }
      // Delete key
      if (e.key === 'Delete' && selectedItem) {
        e.preventDefault();
        handleDeleteItem();
      }
      // F2 - Rename
      if (e.key === 'F2' && selectedItem) {
        e.preventDefault();
        handleRenameItem();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [selectedItem, clipboard]);

  const getCurrentDirectory = () => {
    let current = fileSystem;
    for (let i = 0; i < currentPath.length; i++) {
      current = current[currentPath[i]];
      if (i < currentPath.length - 1 && current.children) {
        current = current.children;
      }
    }
    return current;
  };

  const navigateToFolder = (folderName) => {
    setCurrentPath([...currentPath, folderName]);
    setSelectedItem(null);
  };

  const navigateBack = () => {
    if (currentPath.length > 1) {
      setCurrentPath(currentPath.slice(0, -1));
      setSelectedItem(null);
    }
  };

  const navigateHome = () => {
    setCurrentPath(['C:\\']);
    setSelectedItem(null);
  };

  const navigateToDrive = (drive) => {
    setCurrentPath([drive]);
    setSelectedItem(null);
  };

  const handleNewItem = (type) => {
    setNewItemType(type);
    setNewItemName(type === 'folder' ? 'New Folder' : 'New File.txt');
    setShowNewDialog(true);
  };

  const createNewItem = () => {
    if (!newItemName.trim()) return;

    const newFileSystem = JSON.parse(JSON.stringify(fileSystem));
    let current = newFileSystem;
    
    for (let i = 0; i < currentPath.length; i++) {
      current = current[currentPath[i]];
      if (i < currentPath.length - 1 && current.children) {
        current = current.children;
      }
    }

    if (!current.children) {
      current.children = {};
    }

    // Check if item already exists
    if (current.children[newItemName]) {
      alert('An item with this name already exists');
      return;
    }

    if (newItemType === 'folder') {
      current.children[newItemName] = {
        type: 'folder',
        name: newItemName,
        children: {}
      };
    } else {
      current.children[newItemName] = {
        type: 'file',
        name: newItemName,
        content: '',
        size: '0 KB',
        modified: new Date().toLocaleDateString()
      };
    }

    setFileSystem(newFileSystem);
    setShowNewDialog(false);
    setNewItemName('');
    
    // Notify about file system change
    if (onFileSystemChange) {
      onFileSystemChange(
        newItemType === 'folder' ? 'folder_created' : 'file_created',
        currentPath,
        newItemName
      );
    }
  };

  const handleDeleteItem = () => {
    if (!selectedItem) return;
    
    if (confirm(`Are you sure you want to delete "${selectedItem}"?`)) {
      const newFileSystem = JSON.parse(JSON.stringify(fileSystem));
      let current = newFileSystem;
      
      for (let i = 0; i < currentPath.length; i++) {
        current = current[currentPath[i]];
        if (i < currentPath.length - 1 && current.children) {
          current = current.children;
        }
      }

      if (current.children && current.children[selectedItem]) {
        const itemType = current.children[selectedItem].type;
        delete current.children[selectedItem];
        setFileSystem(newFileSystem);
        setSelectedItem(null);
        
        // Notify about file system change
        if (onFileSystemChange) {
          onFileSystemChange(
            itemType === 'folder' ? 'folder_deleted' : 'file_deleted',
            currentPath,
            selectedItem
          );
        }
      }
    }
  };

  const handleRenameItem = () => {
    if (!selectedItem) return;
    
    const currentDir = getCurrentDirectory();
    const item = currentDir.children[selectedItem];
    setRenameValue(selectedItem);
    setShowRenameDialog(true);
  };

  const performRename = () => {
    if (!renameValue.trim() || renameValue === selectedItem) {
      setShowRenameDialog(false);
      return;
    }

    const newFileSystem = JSON.parse(JSON.stringify(fileSystem));
    let current = newFileSystem;
    
    for (let i = 0; i < currentPath.length; i++) {
      current = current[currentPath[i]];
      if (i < currentPath.length - 1 && current.children) {
        current = current.children;
      }
    }

    if (current.children && current.children[selectedItem]) {
      // Check if new name already exists
      if (current.children[renameValue]) {
        alert('An item with this name already exists');
        return;
      }

      const item = current.children[selectedItem];
      item.name = renameValue;
      current.children[renameValue] = item;
      delete current.children[selectedItem];
      
      setFileSystem(newFileSystem);
      setSelectedItem(renameValue);
      setShowRenameDialog(false);
      setRenameValue('');
      
      // Notify about file system change
      if (onFileSystemChange) {
        onFileSystemChange(
          'item_renamed',
          currentPath,
          `${selectedItem} → ${renameValue}`
        );
      }
    }
  };

  const handleCopy = () => {
    if (!selectedItem) return;
    setClipboard({ type: 'copy', path: [...currentPath], itemName: selectedItem });
  };

  const handleCut = () => {
    if (!selectedItem) return;
    setClipboard({ type: 'cut', path: [...currentPath], itemName: selectedItem });
  };

  const handlePaste = () => {
    if (!clipboard) return;

    const newFileSystem = JSON.parse(JSON.stringify(fileSystem));
    
    // Get source item
    let sourceParent = newFileSystem;
    for (let i = 0; i < clipboard.path.length; i++) {
      sourceParent = sourceParent[clipboard.path[i]];
      if (i < clipboard.path.length - 1 && sourceParent.children) {
        sourceParent = sourceParent.children;
      }
    }
    
    const sourceItem = sourceParent.children[clipboard.itemName];
    if (!sourceItem) return;

    // Get destination
    let destParent = newFileSystem;
    for (let i = 0; i < currentPath.length; i++) {
      destParent = destParent[currentPath[i]];
      if (i < currentPath.length - 1 && destParent.children) {
        destParent = destParent.children;
      }
    }

    if (!destParent.children) {
      destParent.children = {};
    }

    // Handle name collision
    let newName = clipboard.itemName;
    let counter = 1;
    while (destParent.children[newName]) {
      const nameParts = clipboard.itemName.split('.');
      if (nameParts.length > 1) {
        const ext = nameParts.pop();
        newName = nameParts.join('.') + ` (${counter}).` + ext;
      } else {
        newName = clipboard.itemName + ` (${counter})`;
      }
      counter++;
    }

    // Deep clone the item
    destParent.children[newName] = JSON.parse(JSON.stringify(sourceItem));
    destParent.children[newName].name = newName;

    // If cut, remove from source
    if (clipboard.type === 'cut') {
      delete sourceParent.children[clipboard.itemName];
      setClipboard(null);
      
      // Notify about file system change
      if (onFileSystemChange) {
        onFileSystemChange(
          'item_moved',
          currentPath,
          newName
        );
      }
    } else {
      // Notify about file system change
      if (onFileSystemChange) {
        onFileSystemChange(
          'item_copied',
          currentPath,
          newName
        );
      }
    }

    setFileSystem(newFileSystem);
  };

  const currentDir = getCurrentDirectory();
  const items = currentDir.children || {};
  const drives = Object.keys(fileSystem).filter(key => key.endsWith('\\'));

  // Show drives if we're at root level
  const showDrives = currentPath.length === 1 && currentPath[0] === 'C:\\';

  return (
    <div className="flex flex-col h-full bg-white dark:bg-slate-900">
      {/* Navigation Bar */}
      <div className="px-4 py-3 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700">
        <div className="flex items-center gap-2">
          <Button 
            variant="ghost" 
            size="sm"
            className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-30"
            onClick={navigateBack}
            disabled={currentPath.length <= 1}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <Button 
            variant="ghost" 
            size="sm"
            className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
            onClick={navigateHome}
          >
            <Home className="h-4 w-4" />
          </Button>
          <ChevronRight className="h-4 w-4 text-slate-400" />
          
          {/* Address Bar */}
          <div className="flex-1 flex items-center gap-2 bg-slate-50 dark:bg-slate-800 rounded px-3 py-1.5 border border-slate-200 dark:border-slate-700">
            <HardDrive className="h-4 w-4 text-blue-500" />
            <span className="text-sm text-slate-700 dark:text-slate-300">
              {currentPath.join(' > ')}
            </span>
          </div>

          <Button 
            variant="ghost" 
            size="sm"
            className="h-8 w-8 p-0 rounded hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <Search className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {/* Toolbar */}
      <div className="px-4 py-2 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-700 flex items-center gap-2">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button 
              variant="ghost" 
              size="sm"
              className="rounded hover:bg-blue-50 dark:hover:bg-blue-950 hover:text-blue-600"
            >
              <Plus className="h-4 w-4 mr-2" />
              New
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start">
            <DropdownMenuItem onClick={() => handleNewItem('folder')}>
              <FolderPlus className="h-4 w-4 mr-2" />
              Folder
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => handleNewItem('file')}>
              <FilePlus className="h-4 w-4 mr-2" />
              Text File
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        
        <div className="h-4 w-px bg-slate-200 dark:bg-slate-700"></div>
        
        <Button 
          variant="ghost" 
          size="sm"
          className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
          onClick={() => setViewMode(viewMode === 'grid' ? 'list' : 'grid')}
        >
          <Grid3x3 className="h-4 w-4 mr-2" />
          View
        </Button>
        
        {selectedItem && (
          <>
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-700"></div>
            <Button
              variant="ghost"
              size="sm"
              className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
              onClick={handleCopy}
            >
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
              onClick={handleCut}
            >
              <Scissors className="h-4 w-4 mr-2" />
              Cut
            </Button>
          </>
        )}
        
        {clipboard && (
          <Button
            variant="ghost"
            size="sm"
            className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
            onClick={handlePaste}
          >
            <File className="h-4 w-4 mr-2" />
            Paste
          </Button>
        )}
        
        {selectedItem && (
          <>
            <div className="h-4 w-px bg-slate-200 dark:bg-slate-700"></div>
            <Button
              variant="ghost"
              size="sm"
              className="rounded hover:bg-slate-100 dark:hover:bg-slate-800"
              onClick={handleRenameItem}
            >
              <Edit className="h-4 w-4 mr-2" />
              Rename
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="rounded hover:bg-red-50 dark:hover:bg-red-950 hover:text-red-600"
              onClick={handleDeleteItem}
            >
              <Trash2 className="h-4 w-4 mr-2" />
              Delete
            </Button>
          </>
        )}
      </div>

      {/* Sidebar and Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <div className="w-48 border-r border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 p-2 overflow-y-auto">
          <div className="space-y-1">
            <button 
              className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
              onClick={navigateHome}
            >
              <Home className="h-4 w-4" />
              <span>Home</span>
            </button>
            
            <div className="pt-2 pb-1">
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 px-3 py-1">
                This PC
              </div>
            </div>
            
            {drives.map(drive => (
              <button
                key={drive}
                className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors"
                onClick={() => navigateToDrive(drive)}
              >
                <HardDrive className="h-4 w-4" />
                <span>{fileSystem[drive].name}</span>
              </button>
            ))}
            
            <div className="pt-2 pb-1">
              <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 px-3 py-1">
                Quick Access
              </div>
            </div>
            
            <button className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
              <Folder className="h-4 w-4" />
              <span>Documents</span>
            </button>
            <button className="w-full flex items-center gap-2 px-3 py-2 text-sm rounded hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors">
              <Folder className="h-4 w-4" />
              <span>Downloads</span>
            </button>
          </div>
        </div>

        {/* Main Content */}
        <div 
          className="flex-1 overflow-auto p-4"
          onContextMenu={(e) => {
            e.preventDefault();
            setContextMenu({ x: e.clientX, y: e.clientY, type: 'empty' });
          }}
          onClick={() => {
            setContextMenu(null);
            if (selectedItem) setSelectedItem(null);
          }}
        >
          {showDrives ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
              {drives.map(drive => (
                <div
                  key={drive}
                  className={`cursor-pointer p-4 rounded-lg transition-all hover:bg-slate-100 dark:hover:bg-slate-800 ${
                    selectedItem === drive ? 'bg-blue-50 dark:bg-blue-950 ring-2 ring-blue-500' : ''
                  }`}
                  onClick={() => setSelectedItem(drive)}
                  onDoubleClick={() => navigateToDrive(drive)}
                >
                  <div className="flex flex-col items-center">
                    <HardDrive className="h-16 w-16 text-blue-500 mb-2" />
                    <div className="text-sm font-medium text-center">{fileSystem[drive].name}</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
              {Object.keys(items).map((itemName) => {
                const item = items[itemName];
                const isFolder = item.type === 'folder' || item.type === 'drive';
                
                return (
                  <div
                    key={itemName}
                    className={`cursor-pointer p-3 rounded-lg transition-all hover:bg-slate-100 dark:hover:bg-slate-800 ${
                      selectedItem === itemName ? 'bg-blue-50 dark:bg-blue-950 ring-2 ring-blue-500' : ''
                    }`}
                    onClick={() => setSelectedItem(itemName)}
                    onDoubleClick={() => {
                      if (isFolder) {
                        navigateToFolder(itemName);
                      } else if (item.type === 'file' && onOpenFile) {
                        onOpenFile(itemName, item.content || '');
                      }
                    }}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      setSelectedItem(itemName);
                    }}
                  >
                    <div className="flex flex-col items-center">
                      <div className="mb-2">
                        {isFolder ? (
                          <svg className="w-16 h-16" viewBox="0 0 64 64" fill="none">
                            <path d="M8 14C8 11.7909 9.79086 10 12 10H26L30 14H52C54.2091 14 56 15.7909 56 18V50C56 52.2091 54.2091 54 52 54H12C9.79086 54 8 52.2091 8 50V14Z" fill="#FDB022"/>
                            <path d="M8 22C8 19.7909 9.79086 18 12 18H52C54.2091 18 56 19.7909 56 22V50C56 52.2091 54.2091 54 52 54H12C9.79086 54 8 52.2091 8 50V22Z" fill="#FDCA00"/>
                          </svg>
                        ) : (
                          <svg className="w-16 h-16" viewBox="0 0 64 64" fill="none">
                            <path d="M14 8C11.7909 8 10 9.79086 10 12V52C10 54.2091 11.7909 56 14 56H50C52.2091 56 54 54.2091 54 52V20L42 8H14Z" fill="#3B82F6"/>
                            <path d="M42 8V16C42 18.2091 43.7909 20 46 20H54L42 8Z" fill="#60A5FA"/>
                            <rect x="18" y="30" width="28" height="2" rx="1" fill="white" opacity="0.5"/>
                            <rect x="18" y="36" width="28" height="2" rx="1" fill="white" opacity="0.5"/>
                            <rect x="18" y="42" width="20" height="2" rx="1" fill="white" opacity="0.5"/>
                          </svg>
                        )}
                      </div>
                      <div className="text-xs text-center font-medium truncate w-full px-1">
                        {itemName}
                      </div>
                      {item.size && (
                        <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                          {item.size}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {Object.keys(items).length === 0 && !showDrives && (
            <div className="text-center py-20">
              <FolderOpen className="h-20 w-20 mx-auto mb-4 text-slate-300 dark:text-slate-700" />
              <p className="text-slate-500 dark:text-slate-400 font-medium">This folder is empty</p>
            </div>
          )}
        </div>
      </div>

      {/* New Item Dialog */}
      <Dialog open={showNewDialog} onOpenChange={setShowNewDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create New {newItemType === 'folder' ? 'Folder' : 'File'}</DialogTitle>
            <DialogDescription>
              Enter a name for the new {newItemType === 'folder' ? 'folder' : 'file'}
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={newItemName}
              onChange={(e) => setNewItemName(e.target.value)}
              placeholder={newItemType === 'folder' ? 'Folder name' : 'File name'}
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  createNewItem();
                }
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewDialog(false)}>
              Cancel
            </Button>
            <Button onClick={createNewItem}>
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename Dialog */}
      <Dialog open={showRenameDialog} onOpenChange={setShowRenameDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Item</DialogTitle>
            <DialogDescription>
              Enter a new name for the selected item
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              value={renameValue}
              onChange={(e) => setRenameValue(e.target.value)}
              placeholder="New name"
              onKeyPress={(e) => {
                if (e.key === 'Enter') {
                  performRename();
                }
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRenameDialog(false)}>
              Cancel
            </Button>
            <Button onClick={performRename}>
              Rename
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="fixed bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-lg py-1 z-50 min-w-[200px]"
          style={{ left: contextMenu.x, top: contextMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            className="w-full px-4 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2"
            onClick={() => {
              handleNewItem('folder');
              setContextMenu(null);
            }}
          >
            <FolderPlus className="h-4 w-4" />
            New Folder
          </button>
          <button
            className="w-full px-4 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2"
            onClick={() => {
              handleNewItem('file');
              setContextMenu(null);
            }}
          >
            <FilePlus className="h-4 w-4" />
            New File
          </button>
          {clipboard && (
            <>
              <div className="border-t border-slate-200 dark:border-slate-700 my-1"></div>
              <button
                className="w-full px-4 py-2 text-left text-sm hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2"
                onClick={() => {
                  handlePaste();
                  setContextMenu(null);
                }}
              >
                <File className="h-4 w-4" />
                Paste
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
