import { memo } from 'react';

export type SecurityProfile =
  | 'auth'
  | 'dashboard'
  | 'analyze'
  | 'investigation'
  | 'live_threat'
  | 'indicators'
  | 'admin';

export type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical' | 'neutral';

interface SecurityEnvironmentBackgroundProps {
  profile?: SecurityProfile;
  threatLevel?: ThreatLevel;
  activeCount?: number;
  intensity?: 'subtle' | 'moderate' | 'intense';
  className?: string;
}

/*
 * Ambient depth field — CSS-only layered atmosphere.
 * A faint survey grid, a horizon glow tinted by the current threat
 * level, and an edge vignette. No canvas, no JS per frame.
 */
const GLOW: Record<ThreatLevel, string> = {
  safe: 'rgba(62, 207, 142, 0.05)',
  low: 'rgba(76, 158, 235, 0.05)',
  medium: 'rgba(232, 180, 74, 0.05)',
  high: 'rgba(240, 121, 74, 0.07)',
  critical: 'rgba(244, 88, 107, 0.09)',
  neutral: 'rgba(76, 158, 235, 0.04)',
};

const INTENSITY_SCALE = { subtle: 1, moderate: 1.6, intense: 2.4 } as const;

export const SecurityEnvironmentBackground = memo(function SecurityEnvironmentBackground({
  profile = 'dashboard',
  threatLevel = 'neutral',
  intensity = 'subtle',
  className = ''
}: SecurityEnvironmentBackgroundProps) {
  const glow = GLOW[threatLevel] || GLOW.neutral;
  const k = INTENSITY_SCALE[intensity] ?? 1;

  // Admin keeps a faint restricted-identity tint; auth gets a wider,
  // calmer horizon; everything else shares the operations glow.
  const isAuth = profile === 'auth';
  const isAdmin = profile === 'admin';

  return (
    <div
      aria-hidden="true"
      className={`pointer-events-none fixed inset-0 z-0 overflow-hidden ${className}`}
    >
      {/* Survey grid */}
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            'linear-gradient(rgba(255,255,255,0.018) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.018) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }}
      />
      {/* Horizon glow — tinted by current posture */}
      <div
        className="absolute inset-0"
        style={{
          background: `radial-gradient(ellipse ${isAuth ? '70%' : '55%'} ${isAuth ? '55%' : '42%'} at ${isAdmin ? '50%' : '16%'} 0%, ${glow} 0%, transparent 100%)`,
          opacity: k,
        }}
      />
      {/* Counter-glow for depth parity */}
      <div
        className="absolute inset-0"
        style={{
          background: 'radial-gradient(ellipse 45% 38% at 88% 100%, rgba(76,158,235,0.022) 0%, transparent 100%)',
          opacity: k * 0.7,
        }}
      />
      {/* Edge vignette — pulls the deck inward */}
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(ellipse 120% 90% at 50% 40%, transparent 55%, rgba(3,5,9,0.55) 100%)',
        }}
      />
    </div>
  );
});
