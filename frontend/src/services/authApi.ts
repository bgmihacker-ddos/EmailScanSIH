import { apiFetch } from './api';
import { User } from '../types/auth';

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
}

export interface AuthApi {
  register: (payload: any) => Promise<User>;
  login: (payload: any) => Promise<LoginResponse>;
  getMe: () => Promise<User>;
  logout: () => Promise<void>;
  forgotPassword: (email: string) => Promise<{ detail: string }>;
  resetPassword: (payload: any) => Promise<{ detail: string }>;
  verifyEmail: (token: string) => Promise<{ detail: string }>;
  resendVerification: (email: string) => Promise<{ detail: string }>;
  exchangeGoogleCode: (code: string) => Promise<LoginResponse>;
}

export const authApi: AuthApi = {
  register: async (payload) => apiFetch('/api/auth/register', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  login: async (payload) => apiFetch('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  getMe: async () => apiFetch('/api/auth/me', {
    headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
  }),
  logout: async () => {
    localStorage.removeItem('token');
  },
  forgotPassword: async (email) => apiFetch(`/api/auth/forgot-password?email=${encodeURIComponent(email)}`, {
    method: 'POST',
  }),
  resetPassword: async (payload) => apiFetch('/api/auth/reset-password', {
    method: 'POST',
    body: JSON.stringify(payload),
  }),
  verifyEmail: async (token) => apiFetch(`/api/auth/verify-email?token=${encodeURIComponent(token)}`, {
    method: 'POST',
  }),
  resendVerification: async (email) => apiFetch(`/api/auth/resend-verification?email=${encodeURIComponent(email)}`, {
    method: 'POST',
  }),
  exchangeGoogleCode: async (code) => apiFetch('/api/auth/google/exchange', {
    method: 'POST',
    body: JSON.stringify({ code }),
  }),
};
