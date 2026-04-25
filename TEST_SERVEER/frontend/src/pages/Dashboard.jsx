import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
import { AuthContext } from '../context/AuthContext';
import { File, Upload as UploadIcon, Trash2, Edit2, LogOut, Download } from 'lucide-react';

const Dashboard = () => {
  const { user, logout } = useContext(AuthContext);
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [editingId, setEditingId] = useState(null);
  const [newName, setNewName] = useState('');

  const fetchFiles = async () => {
    try {
      const res = await axios.get('http://localhost:5000/files');
      setFiles(res.data);
    } catch (err) {
      setError('Failed to load files');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFiles();
  }, []);

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this file?')) return;
    try {
      await axios.delete(`http://localhost:5000/files/${id}`);
      setFiles(files.filter(f => f.id !== id));
    } catch (err) {
      alert('Failed to delete file');
    }
  };

  const handleRename = async (id) => {
    if (!newName.trim()) {
      setEditingId(null);
      return;
    }
    try {
      const res = await axios.put(`http://localhost:5000/files/${id}`, { newName });
      setFiles(files.map(f => f.id === id ? res.data.file : f));
      setEditingId(null);
    } catch (err) {
      alert('Failed to rename file');
    }
  };

  const startEditing = (file) => {
    setEditingId(file.id);
    setNewName(file.originalName);
  };

  const formatSize = (bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="space-y-6">
      <header className="flex justify-between items-center bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">My Files</h1>
          <p className="text-sm text-gray-500 mt-1">Welcome back, {user?.name || user?.email}</p>
        </div>
        <div className="flex gap-4">
          <Link 
            to="/upload" 
            className="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-sm text-sm font-medium"
          >
            <UploadIcon className="w-4 h-4 mr-2" />
            Upload File
          </Link>
          <button 
            onClick={logout}
            className="inline-flex items-center px-4 py-2 border border-gray-300 bg-white text-gray-700 rounded-lg hover:bg-gray-50 transition-colors shadow-sm text-sm font-medium"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </button>
        </div>
      </header>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg">
          {error}
        </div>
      )}

      {loading ? (
        <div className="flex justify-center items-center py-20">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      ) : files.length === 0 ? (
        <div className="bg-white p-12 rounded-xl border border-gray-100 shadow-sm text-center">
          <div className="mx-auto w-16 h-16 bg-gray-50 rounded-full flex items-center justify-center mb-4">
            <File className="w-8 h-8 text-gray-400" />
          </div>
          <h3 className="text-lg font-medium text-gray-900 mb-2">No files yet</h3>
          <p className="text-gray-500 mb-6">Upload your first file to get started.</p>
          <Link 
            to="/upload" 
            className="inline-flex items-center px-4 py-2 bg-blue-50 text-blue-700 rounded-lg hover:bg-blue-100 transition-colors font-medium"
          >
            Upload a file
          </Link>
        </div>
      ) : (
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Size</th>
                <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Uploaded</th>
                <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {files.map((file) => (
                <tr key={file.id} className="hover:bg-gray-50 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center">
                      <File className="flex-shrink-0 h-5 w-5 text-gray-400 mr-3" />
                      {editingId === file.id ? (
                        <div className="flex items-center gap-2">
                          <input 
                            type="text" 
                            value={newName} 
                            onChange={(e) => setNewName(e.target.value)}
                            className="border border-gray-300 rounded px-2 py-1 text-sm focus:outline-none focus:border-blue-500"
                            autoFocus
                          />
                          <button onClick={() => handleRename(file.id)} className="text-green-600 text-sm font-medium hover:text-green-800">Save</button>
                          <button onClick={() => setEditingId(null)} className="text-gray-500 text-sm font-medium hover:text-gray-700">Cancel</button>
                        </div>
                      ) : (
                        <div className="text-sm font-medium text-gray-900">{file.originalName}</div>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {formatSize(file.size)}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {new Date(file.createdAt).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <div className="flex justify-end gap-3">
                      <a 
                        href={`http://localhost:5000/${file.path}`} 
                        target="_blank" 
                        rel="noreferrer"
                        className="text-blue-600 hover:text-blue-900"
                        title="Download/View"
                      >
                        <Download className="w-4 h-4" />
                      </a>
                      <button 
                        onClick={() => startEditing(file)} 
                        className="text-indigo-600 hover:text-indigo-900"
                        title="Rename"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button 
                        onClick={() => handleDelete(file.id)} 
                        className="text-red-600 hover:text-red-900"
                        title="Delete"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
