
import React, { useState, useEffect } from 'react';
import { AlertCircle, Shield, Upload, LogOut, BarChart3, Plus, Eye, Download, ChevronLeft, ChevronRight } from 'lucide-react';

// ==================== CONFIGURATION ====================
const API_BASE_URL = 'https://api.yourvrmsystem.com'; // Replace with actual backend URL

// ==================== API SERVICE ====================
class ApiService {
  static async signup(userid, email, password) {
    // POST /signup - Creates new user account
    const response = await fetch(`${API_BASE_URL}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, email, password })
    });
    return response.json();
  }

  static async login(userid, password) {

    const response = await fetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, password })
    });
    return response.json();
  }

  static async uploadFile(file, token) {
    // POST /upload - Uploads document and returns S3 key
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await fetch(`${API_BASE_URL}/upload`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      body: formData
    });
    return response.json();
  }

  static async analyzeVendor(vendorName, fileKey, token) {
    // POST /analyze - Triggers VRM analysis
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({ vendorName, fileKey, userToken: token })
    });
    return response.json();
  }

  static async getMyVRMs(token, page = 1, limit = 10) {
    // GET /my-vrms - Retrieves user's VRM assessments
    const response = await fetch(`${API_BASE_URL}/my-vrms?page=${page}&limit=${limit}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  }

  static async getVRMById(id, token) {
    // GET /vrm/:id - Retrieves specific VRM assessment details
    const response = await fetch(`${API_BASE_URL}/vrm/${id}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    return response.json();
  }
}

// ==================== AUTH CONTEXT ====================
const AuthContext = React.createContext(null);

const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const storedToken = window.localStorage.getItem('vrm_token');
    if (storedToken) {
      setToken(storedToken);
      try {
        const payload = JSON.parse(atob(storedToken.split('.')[1]));
        setUser(payload);
      } catch (e) {
        logout();
      }
    }
  }, []);

  const login = (newToken) => {
    window.localStorage.setItem('vrm_token', newToken);
    setToken(newToken);
    try {
      const payload = JSON.parse(atob(newToken.split('.')[1]));
      setUser(payload);
    } catch (e) {
      console.error('Invalid token');
    }
  };

  const logout = () => {
    window.localStorage.removeItem('vrm_token');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ token, user, login, logout, isAuthenticated: !!token }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => React.useContext(AuthContext);

// ==================== LOGIN PAGE ====================
const LoginPage = ({ onNavigate }) => {
  const [userid, setUserid] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await ApiService.login(userid, password);
      
      if (response.token) {
        login(response.token);
        onNavigate('dashboard');
      } else {
        setError(response.message || 'Login failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-slate-800 rounded-2xl shadow-2xl border border-slate-700 p-8">
          <div className="flex justify-center mb-8">
            <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-3 rounded-xl">
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>
          
          <h1 className="text-3xl font-bold text-center text-white mb-2">Welcome Back</h1>
          <p className="text-slate-400 text-center mb-8">Sign in to your VRM account</p>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 mb-6 flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <div className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">User ID</label>
              <input
                type="text"
                value={userid}
                onChange={(e) => setUserid(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="Enter your user ID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="Enter your password"
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-blue-600 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </div>

          <div className="mt-6 text-center">
            <button
              onClick={() => onNavigate('signup')}
              className="text-blue-400 hover:text-blue-300 text-sm font-medium transition"
            >
              Don't have an account? Sign up
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== SIGNUP PAGE ====================
const SignupPage = ({ onNavigate }) => {
  const [userid, setUserid] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    setError('');

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    setLoading(true);

    try {
      const response = await ApiService.signup(userid, email, password);
      
      if (response.success) {
        onNavigate('login');
      } else {
        setError(response.message || 'Signup failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-slate-800 rounded-2xl shadow-2xl border border-slate-700 p-8">
          <div className="flex justify-center mb-8">
            <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-3 rounded-xl">
              <Shield className="w-8 h-8 text-white" />
            </div>
          </div>
          
          <h1 className="text-3xl font-bold text-center text-white mb-2">Create Account</h1>
          <p className="text-slate-400 text-center mb-8">Join our VRM platform today</p>

          {error && (
            <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 mb-6 flex items-start gap-2">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}

          <div className="space-y-5">
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">User ID *</label>
              <input
                type="text"
                value={userid}
                onChange={(e) => setUserid(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="Choose a user ID"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Email (Optional)</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="your.email@example.com"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Password *</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="Create a strong password"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">Confirm Password *</label>
              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                placeholder="Confirm your password"
              />
            </div>

            <button
              onClick={handleSubmit}
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold py-3 px-4 rounded-lg hover:from-blue-600 hover:to-purple-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200"
            >
              {loading ? 'Creating account...' : 'Sign Up'}
            </button>
          </div>

          <div className="mt-6 text-center">
            <button
              onClick={() => onNavigate('login')}
              className="text-blue-400 hover:text-blue-300 text-sm font-medium transition"
            >
              Already have an account? Sign in
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== DASHBOARD PAGE ====================
const DashboardPage = ({ onNavigate, onSelectVRM }) => {
  const [vrms, setVrms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const { token } = useAuth();

  useEffect(() => {
    loadVRMs();
  }, [currentPage]);

  const loadVRMs = async () => {
    setLoading(true);
    try {
      const response = await ApiService.getMyVRMs(token, currentPage, 10);
      setVrms(response.data || []);
      setTotalPages(response.totalPages || 1);
    } catch (err) {
      console.error('Failed to load VRMs:', err);
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level) => {
    const colors = {
      low: 'text-green-400 bg-green-500/10 border-green-500/50',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/50',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/50',
      critical: 'text-red-400 bg-red-500/10 border-red-500/50'
    };
    return colors[level?.toLowerCase()] || colors.medium;
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">VRM Dashboard</h1>
          <p className="text-slate-400">Manage and review your vendor risk assessments</p>
        </div>
        <button
          onClick={() => onNavigate('create')}
          className="flex items-center gap-2 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold px-6 py-3 rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all duration-200"
        >
          <Plus className="w-5 h-5" />
          Create New Assessment
        </button>
      </div>

      {loading ? (
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      ) : vrms.length === 0 ? (
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-12 text-center">
          <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">No assessments yet</h3>
          <p className="text-slate-400 mb-6">Get started by creating your first vendor risk assessment</p>
          <button
            onClick={() => onNavigate('create')}
            className="bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold px-6 py-3 rounded-lg hover:from-blue-600 hover:to-purple-700 transition-all duration-200"
          >
            Create Assessment
          </button>
        </div>
      ) : (
        <>
          <div className="grid gap-4">
            {vrms.map((vrm) => (
              <div
                key={vrm.id}
                className="bg-slate-800 rounded-xl border border-slate-700 p-6 hover:border-slate-600 transition cursor-pointer"
                onClick={() => onSelectVRM(vrm)}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h3 className="text-xl font-semibold text-white mb-2">{vrm.vendorName}</h3>
                    <p className="text-slate-400 text-sm mb-4 line-clamp-2">{vrm.summary}</p>
                    <div className="flex items-center gap-4 text-sm text-slate-400">
                      <span>{new Date(vrm.timestamp).toLocaleDateString()}</span>
                      <span>•</span>
                      <span>{new Date(vrm.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={`px-3 py-1 rounded-lg text-sm font-medium border ${getRiskColor(vrm.riskLevel)}`}>
                      {vrm.riskLevel}
                    </span>
                    <button className="p-2 hover:bg-slate-700 rounded-lg transition">
                      <Eye className="w-5 h-5 text-slate-400" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {totalPages > 1 && (
            <div className="flex justify-center items-center gap-2 mt-8">
              <button
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                disabled={currentPage === 1}
                className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="text-slate-400 px-4">
                Page {currentPage} of {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages}
                className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

// ==================== CREATE VRM PAGE ====================
const CreateVRMPage = ({ onNavigate }) => {
  const [vendorName, setVendorName] = useState('');
  const [file, setFile] = useState(null);
  const [error, setError] = useState('');
  const [uploading, setUploading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const { token } = useAuth();

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    if (!selectedFile) return;

    const validTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    const maxSize = 10 * 1024 * 1024; // 10MB

    if (!validTypes.includes(selectedFile.type)) {
      setError('Invalid file type. Please upload PDF or DOC files only.');
      return;
    }

    if (selectedFile.size > maxSize) {
      setError('File size exceeds 10MB limit.');
      return;
    }

    setFile(selectedFile);
    setError('');
  };

  const handleSubmit = async () => {
    if (!vendorName.trim()) {
      setError('Vendor name is required');
      return;
    }

    if (!file) {
      setError('Please upload a document');
      return;
    }

    setError('');
    setUploading(true);
    setUploadProgress(0);

    try {
      // Simulate upload progress
      const progressInterval = setInterval(() => {
        setUploadProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      const uploadResponse = await ApiService.uploadFile(file, token);
      clearInterval(progressInterval);
      setUploadProgress(100);

      if (!uploadResponse.fileKey) {
        throw new Error('Upload failed');
      }

      setUploading(false);
      setAnalyzing(true);

      const analysisResponse = await ApiService.analyzeVendor(vendorName, uploadResponse.fileKey, token);

      if (analysisResponse.success) {
        onNavigate('dashboard');
      } else {
        setError(analysisResponse.message || 'Analysis failed');
      }
    } catch (err) {
      setError('Operation failed. Please try again.');
    } finally {
      setUploading(false);
      setAnalyzing(false);
      setUploadProgress(0);
    }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Create Vendor Risk Assessment</h1>
        <p className="text-slate-400">Upload vendor documentation for automated risk analysis</p>
      </div>

      <div className="bg-slate-800 rounded-xl border border-slate-700 p-8">
        {error && (
          <div className="bg-red-500/10 border border-red-500/50 rounded-lg p-3 mb-6 flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Vendor Name *</label>
            <input
              type="text"
              value={vendorName}
              onChange={(e) => setVendorName(e.target.value)}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
              placeholder="Enter vendor name"
              disabled={uploading || analyzing}
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">Upload Document *</label>
            <div className="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center hover:border-slate-600 transition">
              <Upload className="w-12 h-12 text-slate-500 mx-auto mb-4" />
              <input
                type="file"
                onChange={handleFileChange}
                accept=".pdf,.doc,.docx"
                className="hidden"
                id="file-upload"
                disabled={uploading || analyzing}
              />
              <label htmlFor="file-upload" className="cursor-pointer">
                <span className="text-blue-400 hover:text-blue-300 font-medium">Click to upload</span>
                <span className="text-slate-400"> or drag and drop</span>
              </label>
              <p className="text-slate-500 text-sm mt-2">PDF or DOC (max 10MB)</p>
              {file && (
                <div className="mt-4 bg-slate-900 rounded-lg p-3 text-left">
                  <p className="text-white text-sm font-medium">{file.name}</p>
                  <p className="text-slate-400 text-xs">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
              )}
            </div>
          </div>

          {uploadProgress > 0 && uploadProgress < 100 && (
            <div>
              <div className="flex justify-between text-sm text-slate-400 mb-2">
                <span>Uploading...</span>
                <span>{uploadProgress}%</span>
              </div>
              <div className="w-full bg-slate-900 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-blue-500 to-purple-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${uploadProgress}%` }}
                />
              </div>
            </div>
          )}

          {analyzing && (
            <div className="bg-blue-500/10 border border-blue-500/50 rounded-lg p-4 flex items-center gap-3">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-400"></div>
              <div>
                <p className="text-blue-400 font-medium">Analyzing document...</p>
                <p className="text-slate-400 text-sm">This may take a few moments</p>
              </div>
            </div>
          )}

          <div className="flex gap-4">
            <button
              onClick={() => onNavigate('dashboard')}
              disabled={uploading || analyzing}
              className="flex-1 px-6 py-3 bg-slate-700 text-white font-semibold rounded-lg hover:bg-slate-600 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              disabled={uploading || analyzing || !vendorName || !file}
              className="flex-1 px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold rounded-lg hover:from-blue-600 hover:to-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {analyzing ? 'Analyzing...' : uploading ? 'Uploading...' : 'Submit for Analysis'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== RESULTS VIEW PAGE ====================
const ResultsViewPage = ({ vrm, onNavigate }) => {
  const getRiskColor = (level) => {
    const colors = {
      low: 'text-green-400 bg-green-500/10 border-green-500/50',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/50',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/50',
      critical: 'text-red-400 bg-red-500/10 border-red-500/50'
    };
    return colors[level?.toLowerCase()] || colors.medium;
  };

  const handleExport = () => {
    const content = `
Vendor Risk Assessment Report
==============================

Vendor Name: ${vrm.vendorName}
Risk Level: ${vrm.riskLevel}
Date: ${new Date(vrm.timestamp).toLocaleString()}

Summary:
${vrm.summary}
    `.trim();

    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VRM_${vrm.vendorName.replace(/\s+/g, '_')}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-4xl mx-auto">
      <button
        onClick={() => onNavigate('dashboard')}
        className="flex items-center gap-2 text-slate-400 hover:text-white mb-6 transition"
      >
        <ChevronLeft className="w-5 h-5" />
        Back to Dashboard
      </button>

      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <div className="bg-gradient-to-r from-blue-500/20 to-purple-600/20 p-8 border-b border-slate-700">
          <div className="flex items-start justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white mb-2">{vrm.vendorName}</h1>
              <p className="text-slate-400">Risk Assessment Report</p>
            </div>
            <span className={`px-4 py-2 rounded-lg font-semibold border ${getRiskColor(vrm.riskLevel)}`}>
              {vrm.riskLevel} Risk
            </span>
          </div>
        </div>

        <div className="p-8 space-y-6">
          <div>
            <h3 className="text-lg font-semibold text-white mb-3">Assessment Details</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-slate-900 rounded-lg p-4">
                <p className="text-slate-400 text-sm mb-1">Vendor Name</p>
                <p className="text-white font-medium">{vrm.vendorName}</p>
              </div>
              <div className="bg-slate-900 rounded-lg p-4">
                <p className="text-slate-400 text-sm mb-1">Assessment Date</p>
                <p className="text-white font-medium">{new Date(vrm.timestamp).toLocaleDateString()}</p>
              </div>
              <div className="bg-slate-900 rounded-lg p-4">
                <p className="text-slate-400 text-sm mb-1">Risk Level</p>
                <p className="text-white font-medium">{vrm.riskLevel}</p>
              </div>
              <div className="bg-slate-900 rounded-lg p-4">
                <p className="text-slate-400 text-sm mb-1">Time</p>
                <p className="text-white font-medium">{new Date(vrm.timestamp).toLocaleTimeString()}</p>
              </div>
            </div>
          </div>

          <div>
            <h3 className="text-lg font-semibold text-white mb-3">Risk Summary</h3>
            <div className="bg-slate-900 rounded-lg p-6">
              <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">{vrm.summary}</p>
            </div>
          </div>

          <div className="flex gap-4">
            <button
              onClick={handleExport}
              className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 text-white font-semibold rounded-lg hover:from-blue-600 hover:to-purple-700 transition"
            >
              <Download className="w-5 h-5" />
              Export Report
            </button>
            <button
              onClick={() => onNavigate('dashboard')}
              className="flex items-center gap-2 px-6 py-3 bg-slate-700 text-white font-semibold rounded-lg hover:bg-slate-600 transition"
            >
              Back to Dashboard
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// ==================== MAIN APP ====================
export default function App() {
  const [currentPage, setCurrentPage] = useState('login');
  const [selectedVRM, setSelectedVRM] = useState(null);

  return (
    <AuthProvider>
      <AppContent 
        currentPage={currentPage} 
        setCurrentPage={setCurrentPage}
        selectedVRM={selectedVRM}
        setSelectedVRM={setSelectedVRM}
      />
    </AuthProvider>
  );
}

const AppContent = ({ currentPage, setCurrentPage, selectedVRM, setSelectedVRM }) => {
  const { isAuthenticated, logout } = useAuth();

  useEffect(() => {
    if (!isAuthenticated && !['login', 'signup'].includes(currentPage)) {
      setCurrentPage('login');
    }
  }, [isAuthenticated, currentPage, setCurrentPage]);

  const handleSelectVRM = (vrm) => {
    setSelectedVRM(vrm);
    setCurrentPage('results');
  };

  const renderPage = () => {
    if (!isAuthenticated) {
      if (currentPage === 'signup') {
        return <SignupPage onNavigate={setCurrentPage} />;
      }
      return <LoginPage onNavigate={setCurrentPage} />;
    }

    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
        <nav className="bg-slate-800/50 backdrop-blur-lg border-b border-slate-700 sticky top-0 z-50">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
              <div className="flex items-center gap-3">
                <div className="bg-gradient-to-br from-blue-500 to-purple-600 p-2 rounded-lg">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <span className="text-xl font-bold text-white">VRM System</span>
              </div>
              
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setCurrentPage('dashboard')}
                  className={`px-4 py-2 rounded-lg font-medium transition ${
                    currentPage === 'dashboard'
                      ? 'bg-blue-500 text-white'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  <BarChart3 className="w-4 h-4 inline mr-2" />
                  Dashboard
                </button>
                <button
                  onClick={() => setCurrentPage('create')}
                  className={`px-4 py-2 rounded-lg font-medium transition ${
                    currentPage === 'create'
                      ? 'bg-blue-500 text-white'
                      : 'text-slate-300 hover:text-white hover:bg-slate-700'
                  }`}
                >
                  <Plus className="w-4 h-4 inline mr-2" />
                  Create VRM
                </button>
                <button
                  onClick={() => {
                    logout();
                    setCurrentPage('login');
                  }}
                  className="px-4 py-2 rounded-lg font-medium text-red-400 hover:text-red-300 hover:bg-slate-700 transition"
                >
                  <LogOut className="w-4 h-4 inline mr-2" />
                  Logout
                </button>
              </div>
            </div>
          </div>
        </nav>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {currentPage === 'dashboard' && (
            <DashboardPage onNavigate={setCurrentPage} onSelectVRM={handleSelectVRM} />
          )}
          {currentPage === 'create' && (
            <CreateVRMPage onNavigate={setCurrentPage} />
          )}
          {currentPage === 'results' && selectedVRM && (
            <ResultsViewPage vrm={selectedVRM} onNavigate={setCurrentPage} />
          )}
        </div>
      </div>
    );
  };

  return renderPage();

}







