import React from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

/**
 * VulnWatch Error Boundary
 * Catches any React rendering errors and shows a clean recovery UI
 * instead of a blank white screen.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('[VulnWatch ErrorBoundary]', error, info.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#050811] flex items-center justify-center p-8">
          <div className="max-w-lg w-full cyber-glass-card rounded-2xl p-8 border border-rose-500/40 text-center space-y-5">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-rose-950/80 border border-rose-500/40 mx-auto cyber-glow-red">
              <ShieldAlert className="w-8 h-8 text-rose-400" />
            </div>
            <div>
              <h1 className="font-orbitron font-bold text-xl text-white mb-2">
                SYSTEM FAULT DETECTED
              </h1>
              <p className="text-xs font-mono text-slate-400 leading-relaxed">
                A critical rendering error occurred in the VulnWatch HUD. This is likely a temporary issue.
              </p>
              {this.state.error && (
                <pre className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-rose-300 text-left overflow-x-auto max-h-32">
                  {this.state.error.message}
                </pre>
              )}
            </div>
            <div className="flex gap-3 justify-center">
              <button
                onClick={this.handleReset}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-black font-orbitron font-bold text-xs flex items-center gap-2 transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>RETRY MODULE</span>
              </button>
              <button
                onClick={() => window.location.reload()}
                className="px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs transition-colors cursor-pointer"
              >
                Full Reload
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
