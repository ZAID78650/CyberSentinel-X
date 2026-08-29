import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("[ErrorBoundary] Component error:", error, errorInfo);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  handleReload = () => {
    window.location.reload();
  };

  isChunkLoadError(error: Error | null): boolean {
    if (!error) return false;
    const msg = error.message || "";
    return msg.includes("dynamically imported module") || msg.includes("Failed to fetch") || error.name === "ChunkLoadError";
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      const isChunk = this.isChunkLoadError(this.state.error);

      return (
        <div className="glass flex flex-col items-center justify-center p-8 text-center">
          <AlertTriangle className="mb-4 h-12 w-12 text-cyber-red" />
          <h2 className="text-lg font-bold text-slate-200">Something went wrong</h2>
          <p className="mt-2 max-w-md text-sm text-slate-400">
            {isChunk
              ? "Failed to load a page module. This usually happens after a new deployment."
              : "A component encountered an error. This is usually caused by a network issue or a rendering problem."}
          </p>
          {this.state.error && (
            <pre className="mt-3 max-w-lg overflow-auto rounded border p-3 text-left text-[11px] text-slate-500" style={{ borderColor: "var(--surface-border)", background: "var(--surface-raised)" }}>
              {this.state.error.message}
            </pre>
          )}
          <div className="mt-5 flex gap-3">
            <button onClick={isChunk ? this.handleReload : this.handleRetry} className="btn-primary gap-2">
              <RefreshCw className="h-4 w-4" /> {isChunk ? "Reload Page" : "Try Again"}
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
