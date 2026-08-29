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

  isChunkLoadError(error: Error): boolean {
    return (
      error?.message?.includes("dynamically imported module") ||
      error?.message?.includes("Failed to fetch") ||
      error?.name === "ChunkLoadError"
    );
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;

      const isChunk = this.state.error && this.isChunkLoadError(this.state.error);

      return (
        <div className="intel-card flex flex-col items-center justify-center p-8 text-center">
          <AlertTriangle className="mb-4 h-12 w-12 text-red-400" />
          <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>Something went wrong</h2>
          <p className="mt-2 max-w-md text-sm" style={{ color: "var(--text-secondary)" }}>
            {isChunk
              ? "Failed to load a page module. This usually happens after a new deployment."
              : "A component encountered an error. This is usually caused by a network issue or a rendering problem."}
          </p>
          {this.state.error && (
            <pre className="mt-3 max-w-lg overflow-auto rounded border p-3 text-left text-2xs" style={{ borderColor: "var(--border-primary)", background: "var(--bg-tertiary)", color: "var(--text-muted)", maxWidth: 400 }}>
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
