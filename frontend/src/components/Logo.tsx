export function Logo({ size = 32, collapsed = false }: { size?: number; collapsed?: boolean }) {
  return (
    <div className="flex items-center gap-2.5">
      <div className="relative shrink-0" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-label="CyberSentinel X logo">
          <defs>
            <linearGradient id="csxGrad" x1="0" y1="0" x2="48" y2="48">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="50%" stopColor="#06b6d4" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
            <linearGradient id="csxFill" x1="0" y1="0" x2="48" y2="48">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.15" />
              <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.1" />
            </linearGradient>
            <clipPath id="csxClip">
              <path d="M24 3 L42 10 V24 C42 35 34 42 24 45 C14 42 6 35 6 24 V10 Z" />
            </clipPath>
          </defs>
          {/* Shield */}
          <path
            d="M24 3 L42 10 V24 C42 35 34 42 24 45 C14 42 6 35 6 24 V10 Z"
            fill="url(#csxFill)"
            stroke="url(#csxGrad)"
            strokeWidth="2"
          />
          {/* Scanline */}
          <g clipPath="url(#csxClip)">
            <rect x="-4" y="-6" width="56" height="2" fill="#06b6d4" opacity="0.6">
              <animate attributeName="y" values="-6;48" dur="3s" repeatCount="indefinite" />
            </rect>
          </g>
          {/* Inner hexagon */}
          <path
            d="M24 12 L33 17 V27 L24 33 L15 27 V17 Z"
            stroke="#06b6d4"
            strokeWidth="1.5"
            fill="none"
            strokeDasharray="90"
            strokeDashoffset="90"
          >
            <animate attributeName="stroke-dashoffset" values="90;0" dur="2s" fill="freeze" />
          </path>
          {/* Eye / lens */}
          <circle cx="24" cy="22" r="3.5" fill="#3b82f6" opacity="0.9" />
          <path d="M24 25.5 V30" stroke="#06b6d4" strokeWidth="1.5" strokeLinecap="round" />
          {/* Crosshair */}
          <path d="M18 17 L16 15 M30 17 L32 15 M15 22 H12 M33 22 H36" stroke="#8b5cf6" strokeWidth="1.2" strokeLinecap="round" opacity="0.7" />
        </svg>
      </div>
      {!collapsed && (
        <div className="min-w-0 leading-tight">
          <span className="block text-sm font-extrabold tracking-tight text-gradient-blue">
            CYBERSENTINEL
          </span>
          <span className="block text-2xs font-semibold uppercase tracking-[0.3em]" style={{ color: "var(--text-muted)" }}>
            X · Predictive Intelligence
          </span>
        </div>
      )}
    </div>
  );
}

export function HeroLogo({ size = 80 }: { size?: number }) {
  return (
    <div className="flex flex-col items-center gap-4">
      <div className="relative">
        <div className="absolute inset-0 -z-10 scale-150 rounded-full blur-2xl" style={{ background: "rgba(59, 130, 246, 0.15)" }} />
        <Logo size={size} />
      </div>
      <div className="text-center">
        <p className="text-2xl font-black tracking-tight text-gradient-intel">
          CYBERSENTINEL X
        </p>
        <p className="mt-1 text-xs font-semibold uppercase tracking-[0.4em]" style={{ color: "var(--text-muted)" }}>
          Predictive Cybercrime Intelligence
        </p>
        <p className="mt-2 text-2xs font-medium tracking-wider" style={{ color: "var(--text-secondary)" }}>
          Predict · Protect · Prevent
        </p>
      </div>
    </div>
  );
}
