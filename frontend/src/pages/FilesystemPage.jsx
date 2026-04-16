import React from 'react';
import FileSystemTree from '../components/FileSystemTree';

export default function FilesystemPage({ newEvent, connected }) {
  return (
    <div className="flex-1 flex flex-col p-6 overflow-hidden">
      <div className="mb-4">
        <h2 className="text-white text-xl font-semibold">Filesystem Monitor</h2>
        <p className="text-gray-500 text-sm">
          Live directory tree — canary locations, alert hotspots, and entropy scores
        </p>
      </div>
      <div className="flex-1 overflow-hidden">
        <FileSystemTree newEvent={newEvent} connected={connected} />
      </div>
    </div>
  );
}
