export function Logo({ size = 36, withText = true }: { size?: number; withText?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-label="CyberSentinel X logo" className="relative z-10">
          <defs>
            <linearGradient id="csxGrad" x1="0" y1="0" x2="48" y2="48">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="50%" stopColor="#22d3ee" />
              <stop offset="100%" stopColor="#a78bfa" />
            </linearGradient>
            <linearGradient id="csxShieldFill" x1="0" y1="0" x2="48" y2="48">
              <stop offset="0%" stopColor="#0ea5e9" stopOpacity="0.28" />
              <stop offset="100%" stopColor="#7c3aed" stopOpacity="0.18" />
            </linearGradient>
            <radialGradient id="csxGlow" cx="50%" cy="40%" r="60%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
            </radialGradient>
            <clipPath id="csxClip">
              <path d="M24 3 L42 10 V24 C42 35 34 42 24 45 C14 42 6 35 6 24 V10 Z" />
            </clipPath>
          </defs>

          {/* ambient glow behind the shield */}
          <circle cx="24" cy="24" r="22" fill="url(#csxGlow)">
            <animate attributeName="r" values="20;24;20" dur="3s" repeatCount="indefinite" />
          </circle>

          {/* Shield */}
          <path
            d="M24 3 L42 10 V24 C42 35 34 42 24 45 C14 42 6 35 6 24 V10 Z"
            fill="url(#csxShieldFill)"
            stroke="url(#csxGrad)"
            strokeWidth="2.4"
          />

          {/* scanline sweep across the shield */}
          <g clipPath="url(#csxClip)">
            <rect x="-4" y="-6" width="56" height="3" fill="#22d3ee" opacity="0.75">
              <animate attributeName="y" values="-6;48" dur="2.6s" repeatCount="indefinite" />
            </rect>
          </g>

          {/* Inner hex / sentinel */}
          <path
            d="M24 12 L33 17 V27 L24 33 L15 27 V17 Z"
            stroke="#22d3ee"
            strokeWidth="1.8"
            fill="none"
            strokeDasharray="90"
            strokeDashoffset="90"
          >
            <animate attributeName="stroke-dashoffset" values="90;0" dur="1.8s" repeatCount="indefinite" />
          </path>
          <circle cx="24" cy="22" r="4" fill="#38bdf8">
            <animate attributeName="r" values="3.6;4.2;3.6" dur="1.4s" repeatCount="indefinite" />
          </circle>
          <path d="M24 26 V31" stroke="#22d3ee" strokeWidth="1.8" strokeLinecap="round" />
          {/* Crosshair ticks */}
          <path d="M18 17 L16 15 M30 17 L32 15 M15 22 H12 M33 22 H36" stroke="#a78bfa" strokeWidth="1.4" strokeLinecap="round" />
        </svg>
      </div>
      {withText && (
        <div className="leading-tight">
          <span className="block bg-gradient-to-r from-electric-400 via-cyber-cyan to-cyber-purple bg-clip-text text-base font-extrabold tracking-tight text-transparent drop-shadow-[0_0_8px_rgba(56,189,248,0.35)]">
            CYBERSENTINEL
          </span>
          <span className="block text-[10px] font-semibold uppercase tracking-[0.35em] text-cyber-cyan">
            X · SOC Platform
          </span>
        </div>
      )}
    </div>
  );
}

/** Full-width hero logo used on the auth pages. */
export function HeroLogo({ size = 88 }: { size?: number }) {
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative">
        <div className="absolute inset-0 -z-10 scale-150 rounded-full bg-electric-500/20 blur-2xl" />
        <Logo size={size} withText={false} />
      </div>
      <div className="text-center">
        <p className="bg-gradient-to-r from-electric-400 via-cyber-cyan to-cyber-purple bg-clip-text text-2xl font-black tracking-tight text-transparent drop-shadow-[0_0_12px_rgba(56,189,248,0.4)]">
          CYBERSENTINEL X
        </p>
        <p className="mt-1 text-[11px] font-semibold uppercase tracking-[0.4em] text-slate-500">
          Agentic AI SOC Platform
        </p>
      </div>
    </div>
  );
}
