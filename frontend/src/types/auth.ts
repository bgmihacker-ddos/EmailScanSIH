export type Role = 'user' | 'admin';

export interface User {
  id: string;
  email: string;
  role: Role;
  name: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
}
