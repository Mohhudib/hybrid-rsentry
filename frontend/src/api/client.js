import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

// Events
export const getEvents = (params = {}) => api.get('/api/events', { params });
export const getEvent = (id) => api.get(`/api/events/${id}`);

// Alerts
export const getAlerts = (params = {}) => api.get('/api/alerts', { params });
export const getAlert = (id) => api.get(`/api/alerts/${id}`);
export const acknowledgeAlert = (id) => api.patch(`/api/alerts/${id}/acknowledge`);
export const analyzeAlert = (id) => api.post(`/api/alerts/${id}/analyze`);
export const getAlertEvidence = (id) => api.get(`/api/alerts/${id}/evidence`);
export const forensicExport = (id) => api.get(`/api/alerts/${id}/forensic-export`);

// Hosts
export const getHosts = (params = {}) => api.get('/api/hosts', { params });
export const getHost = (id) => api.get(`/api/hosts/${id}`);
export const getHostRisk = (id) => api.get(`/api/hosts/${id}/risk`);
export const containHost = (id) => api.post(`/api/hosts/${id}/contain`);
export const releaseHost = (id) => api.delete(`/api/hosts/${id}/contain`);

export default api;
