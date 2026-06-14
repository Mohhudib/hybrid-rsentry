import axios from 'axios';

const API_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

// Events
export const getEvents = (params = {}) => api.get('/api/events', { params });

// Alerts
export const getAlerts = (params = {}) => api.get('/api/alerts', { params });
export const acknowledgeAllAlerts = () => api.post('/api/alerts/acknowledge-all');
export const clearAllAlerts = () => api.post('/api/alerts/clear-all');
export const acknowledgeAlert = (id) => api.patch(`/api/alerts/${id}/acknowledge`);
export const analyzeAlert = (id) => api.post(`/api/alerts/${id}/analyze`);
export const getAlertEvidence = (id, signal) => api.get(`/api/alerts/${id}/evidence`, { signal });
export const forensicExport = (id) => api.get(`/api/alerts/${id}/forensic-export`);

// Hosts
export const getHosts = (params = {}) => api.get('/api/hosts', { params });
export const getHost = (id, signal) => api.get(`/api/hosts/${id}`, signal ? { signal } : {});
export const getHostRisk = (id) => api.get(`/api/hosts/${id}/risk`);
export const containHost = (id) => api.post(`/api/hosts/${id}/contain`);
export const releaseHost = (id) => api.delete(`/api/hosts/${id}/contain`);

export default api;
