import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { authApi } from '../services/authApi';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext';

export default function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { checkAuth } = useAuth();
  const { addToast } = useToast();

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      addToast('Authentication failed: Missing code', 'error');
      navigate('/login');
      return;
    }

    const exchangeCode = async () => {
      try {
        const response = await authApi.exchangeGoogleCode(code);
        localStorage.setItem('token', response.access_token);
        await checkAuth();
        navigate('/');
      } catch (err: any) {
        addToast('Authentication failed: ' + (err.message || 'Invalid code'), 'error');
        navigate('/login');
      }
    };

    exchangeCode();
  }, [searchParams, navigate, checkAuth, addToast]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-sunken text-ink">
      Processing authentication...
    </div>
  );
}
