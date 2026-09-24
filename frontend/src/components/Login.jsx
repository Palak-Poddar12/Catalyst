import { useState } from "react";
import {
  ArrowRight,
  Eye,
  EyeOff,
  Globe2,
  LockKeyhole,
  Mail,
  Network,
  Search,
  ShieldCheck,
  Sparkles,
} from "lucide-react";

import "./Login.css";

function Login({ onLogin, onBack }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");

    const normalizedEmail = email.trim().toLowerCase();

    if (!normalizedEmail || !normalizedEmail.includes("@")) {
      setError("Enter a valid investigator email address.");
      return;
    }

    if (password.length < 8) {
      setError("Password must contain at least 8 characters.");
      return;
    }

    setIsSubmitting(true);

    // Prototype-only authentication. Replace this handler with the
    // SatGuard auth API when the backend authentication service is added.
    await new Promise((resolve) => setTimeout(resolve, 450));

    if (rememberMe) {
      localStorage.setItem("satguard_authenticated", "true");
    } else {
      sessionStorage.setItem("satguard_authenticated", "true");
    }

    localStorage.setItem("satguard_user_email", normalizedEmail);
    onLogin(normalizedEmail);
    setIsSubmitting(false);
  };

  return (
    <main className="login-page">
      {onBack && (
        <button className="login-back-button" type="button" onClick={onBack}>← Back to SatGuard</button>
      )}
      <section className="login-visual-panel" aria-label="SatGuard overview">
        <div className="visual-glow visual-glow-one" />
        <div className="visual-glow visual-glow-two" />
        <div className="network-grid" />

        <header className="login-brand brand-light">
          <div className="login-logo-mark">
            <ShieldCheck size={28} strokeWidth={2.2} />
          </div>
          <div>
            <div className="login-brand-name">
              SAT<span>GUARD</span>
            </div>
            <p>Email Threat Intelligence &amp; Forensics</p>
          </div>
        </header>

        <div className="visual-content">
          <div className="visual-kicker">
            <Sparkles size={14} />
            Evidence-driven security investigation
          </div>

          <h1>
            Investigate.<br />
            Correlate.<br />
            <span>Protect.</span>
          </h1>

          <p className="visual-description">
            Analyze suspicious emails, preserve evidence, trace threat
            infrastructure, and connect related indicators in one forensic
            workspace.
          </p>

          <div className="login-capabilities">
            <div>
              <span className="capability-icon"><Search size={17} /></span>
              <strong>Detect</strong>
              <small>Threat signals</small>
            </div>
            <div>
              <span className="capability-icon"><Network size={17} /></span>
              <strong>Correlate</strong>
              <small>Infrastructure</small>
            </div>
            <div>
              <span className="capability-icon"><ShieldCheck size={17} /></span>
              <strong>Investigate</strong>
              <small>Forensic evidence</small>
            </div>
          </div>
        </div>

        <div className="threat-orbit orbit-one">
          <span><Mail size={15} /></span>
          <div>
            <strong>Suspicious Email</strong>
            <small>High risk signal</small>
          </div>
        </div>

        <div className="threat-orbit orbit-two">
          <span><Network size={15} /></span>
          <div>
            <strong>Threat Infrastructure</strong>
            <small>Correlation detected</small>
          </div>
        </div>

        <div className="threat-orbit orbit-three">
          <span><Globe2 size={15} /></span>
          <div>
            <strong>Source IP</strong>
            <small>Evidence mapped</small>
          </div>
        </div>

        <div className="login-visual-footer">
          <span />
          Real threats. Real evidence. A safer digital world.
        </div>
      </section>

      <section className="login-form-panel">
        <div className="language-selector">
          <Globe2 size={16} />
          <span>English</span>
          <span className="language-chevron">⌄</span>
        </div>

        <div className="login-form-wrap">
          <div className="login-mobile-brand">
            <div className="login-logo-mark">
              <ShieldCheck size={24} />
            </div>
            <div>
              <div className="login-brand-name dark-brand">SAT<span>GUARD</span></div>
              <p>Email Threat Intelligence &amp; Forensics</p>
            </div>
          </div>

          <div className="form-intro">
            <p className="form-eyebrow">Secure investigator access</p>
            <h2>Welcome Back</h2>
            <p>Sign in to your SatGuard account</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <label className="login-field">
              <span>Email Address</span>
              <div className="input-shell">
                <Mail size={18} />
                <input
                  type="email"
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="Enter your email address"
                  autoComplete="email"
                />
              </div>
            </label>

            <label className="login-field">
              <span>Password</span>
              <div className="input-shell">
                <LockKeyhole size={18} />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                />
                <button
                  className="password-toggle"
                  type="button"
                  onClick={() => setShowPassword((value) => !value)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </div>
            </label>

            <div className="login-options">
              <label className="remember-option">
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={(event) => setRememberMe(event.target.checked)}
                />
                <span>Remember me</span>
              </label>
              <button type="button" className="text-link" onClick={() => setError("Password recovery will be connected to the authentication service.")}>
                Forgot password?
              </button>
            </div>

            {error && <div className="login-error" role="alert">{error}</div>}

            <button className="sign-in-button" type="submit" disabled={isSubmitting}>
              <span>{isSubmitting ? "Signing In..." : "Sign In"}</span>
              <ArrowRight size={19} />
            </button>
          </form>

          <div className="login-divider"><span>or</span></div>

          <button
            type="button"
            className="google-button"
            onClick={() => setError("Google authentication will be connected separately from Gmail authorization.")}
          >
            <span className="google-mark">G</span>
            Continue with Google
          </button>

          <p className="create-account">
            Don&apos;t have an account?{" "}
            <button type="button" onClick={() => setError("Account creation will be connected to the SatGuard authentication service.")}>Create account</button>
          </p>

          <p className="security-note">
            <LockKeyhole size={13} />
            Your SatGuard account is separate from Gmail authorization.
          </p>
        </div>
      </section>
    </main>
  );
}

export default Login;
