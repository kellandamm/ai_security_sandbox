import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export default class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("App render failed", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-slate-950 p-6 text-white">
          <div className="max-w-lg rounded-lg border border-red-400/40 bg-slate-900 p-5 shadow-xl">
            <h1 className="text-lg font-semibold">The chat UI hit a rendering error.</h1>
            <p className="mt-2 text-sm text-slate-300">
              Refresh the page to continue. The run may still have completed, so check Azure with the last run ID if needed.
            </p>
            <pre className="mt-4 max-h-44 overflow-auto rounded bg-black/40 p-3 text-xs text-red-100">
              {this.state.error.message}
            </pre>
            <button
              className="mt-4 rounded bg-blue-500 px-3 py-2 text-sm font-medium text-white hover:bg-blue-400"
              type="button"
              onClick={() => window.location.reload()}
            >
              Refresh
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}