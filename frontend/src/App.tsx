
import { useEffect, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import './App.css';

const API = 'http://127.0.0.1:8000';

type Tab = 'checker' | 'dashboard';
type Verdict = 'phishing' | 'legitimate';

type Result = {
  url: string;
  verdict: 'phishing' | 'legitimate';
  confidence: number;
  stage_used: string;
  reasons?: string[];
};

type Stats = {
  total_scans: number;
  phishing_blocked: number;
  recent: Array<{
    url: string;
    verdict: Verdict;
    confidence: number;
    ts: string;
  }>;
  top_reported: Array<{
    domain: string;
    count: number;
  }>;
};

async function request<T>(
  path: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(`${API}${path}`, options);

  if (!response.ok) {
    throw new Error(
      `Request failed (${response.status}). Please try again.`
    );
  }

  return response.json() as Promise<T>;
}

function Icon({
  name,
  size = 20,
}: {
  name: string;
  size?: number;
}) {
  const paths: Record<string, ReactNode> = {
    shield: (
      <>
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z" />
        <path d="m9 12 2 2 4-4" />
      </>
    ),
    scan: (
      <>
        <path d="M4 7V5a1 1 0 0 1 1-1h2" />
        <path d="M17 4h2a1 1 0 0 1 1 1v2" />
        <path d="M20 17v2a1 1 0 0 1-1 1h-2" />
        <path d="M7 20H5a1 1 0 0 1-1-1v-2" />
        <path d="M7 12h10" />
      </>
    ),
    chart: (
      <>
        <path d="M3 3v18h18" />
        <path d="m19 9-5 5-4-4-5 5" />
      </>
    ),
    link: (
      <>
        <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
        <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
      </>
    ),
    alert: (
      <>
        <path d="m10.3 3.86-8.1 14A2 2 0 0 0 3.93 21h16.14a2 2 0 0 0 1.73-3.14l-8.1-14a2 2 0 0 0-3.4 0Z" />
        <path d="M12 9v4" />
        <path d="M12 17h.01" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    arrow: (
      <>
        <path d="M7 17 17 7" />
        <path d="M7 7h10v10" />
      </>
    ),
    refresh: (
      <>
        <path d="M20 7v5h-5" />
        <path d="M4 17v-5h5" />
        <path d="M5.6 9a7 7 0 0 1 11.5-2.6L20 12M4 12l2.9 5.6A7 7 0 0 0 18.4 15" />
      </>
    ),
    clock: (
      <>
        <circle cx="12" cy="12" r="10" />
        <path d="M12 6v6l4 2" />
      </>
    ),
    lock: (
      <>
        <rect width="14" height="11" x="5" y="11" rx="2" />
        <path d="M8 11V7a4 4 0 1 1 8 0v4" />
      </>
    ),
  };

  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {paths[name] ?? paths.shield}
    </svg>
  );
}

const STAGE_LABEL: Record<string, string> = {
  stage1_fast: 'Stage 1 · fast analysis',
  stage2_deep: 'Stage 2 · deep analysis',
  allowlist: 'Trusted domain allowlist',
};

function stageLabel(stage: string) {
  return STAGE_LABEL[stage] ?? stage;
}

export default function App() {
  const [tab, setTab] = useState<Tab>('checker');
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);

  useEffect(() => {
    let active = true;

    request<{ status: string }>('/')
      .then(() => {
        if (active) setApiOnline(true);
      })
      .catch(() => {
        if (active) setApiOnline(false);
      });

    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#home" aria-label="Sentinel home">
          <span className="brand-mark">
            <Icon name="shield" size={23} />
          </span>
          <span className="brand-name">Defender</span>
        </a>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="side-nav" aria-label="Main navigation">
          <button
            className={tab === 'checker' ? 'nav-item active' : 'nav-item'}
            onClick={() => setTab('checker')}
          >
            <Icon name="scan" size={18} />
            URL Scanner
          </button>

          <button
            className={tab === 'dashboard' ? 'nav-item active' : 'nav-item'}
            onClick={() => setTab('dashboard')}
          >
            <Icon name="chart" size={18} />
            Threat overview
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-status">
            <span
              className={`status-dot ${apiOnline === true
                ? 'online'
                : apiOnline === false
                  ? 'offline'
                  : ''
                }`}
            />

            <div>
              <strong>
                {apiOnline === true
                  ? 'API connected'
                  : apiOnline === false
                    ? 'API unavailable'
                    : 'Connecting…'}
              </strong>
              <span>Local protection service</span>
            </div>
          </div>

          <div className="sidebar-footnote">
            <Icon name="lock" size={14} />
            Your scans stay on this machine
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            SECURITY CENTER
            <span>/</span>
            {tab === 'checker' ? 'URL SCANNER' : 'THREAT OVERVIEW'}
          </div>

          <div className="topbar-live">
            <span
              className={`status-dot ${apiOnline === true
                ? 'online'
                : apiOnline === false
                  ? 'offline'
                  : ''
                }`}
            />

            {apiOnline === true
              ? 'SYSTEM OPERATIONAL'
              : apiOnline === false
                ? 'BACKEND OFFLINE'
                : 'CHECKING STATUS'}
          </div>
        </header>

        <div className="page-content">
          {tab === 'checker' ? <Checker /> : <Dashboard />}
        </div>

        <footer className="page-footer">
          <span>SENTINEL SECURITY</span>
          <span>Defence starts with awareness.</span>
        </footer>
      </main>
    </div>
  );
}

function Checker() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<Result | null>(null);
  const [loading, setLoading] = useState(false);
  const [reporting, setReporting] = useState(false);
  const [reported, setReported] = useState(false);
  const [error, setError] = useState('');
  const [reportMessage, setReportMessage] = useState('');

  const check = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    const trimmedUrl = url.trim();

    if (!trimmedUrl) return;

    setLoading(true);
    setResult(null);
    setError('');
    setReportMessage('');
    setReported(false);

    try {
      const prediction = await request<Result>('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmedUrl }),
      });

      setResult(prediction);

    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not reach the security service.'
      );
    } finally {
      setLoading(false);
    }
  };

  const report = async () => {
    if (!result || result.verdict !== 'phishing') return;

    let domain: string;

    try {
      const normalizedUrl = result.url.includes('://')
        ? result.url
        : `http://${result.url}`;

      domain = new URL(normalizedUrl).hostname;

      if (!domain) {
        throw new Error('Invalid domain');
      }
    } catch {
      setError('Could not read a domain from this URL.');
      return;
    }

    setReporting(true);
    setError('');
    setReportMessage('');

    try {
      const response = await request<{
        domain: string;
        total_reports: number;
      }>('/report', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          domain,
          reason: 'reported from web scanner',
        }),
      });

      setReported(true);

      setReportMessage(
        `Report received for ${response.domain}. Community reports: ${response.total_reports}.`
      );
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not submit the report.'
      );
    } finally {
      setReporting(false);
    }
  };

  return (
    <>
      <section className="hero">
        <div className="eyebrow">
          <span className="eyebrow-line" />
          REAL-TIME THREAT INTELLIGENCE
        </div>

        <h1>
          Know what’s
          <br />
          <span>behind the link.</span>
        </h1>

        <p className="hero-copy">
          Inspect suspicious URLs with layered machine-learning analysis
          before you click.
        </p>

        {/* URL Scanner Form */}
        <form className="scanner-form" onSubmit={check}>
          <div className="url-input-wrap">
            <Icon name="link" size={19} />

            <input
              aria-label="URL to scan"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              placeholder="Paste a URL, e.g. https://example.com/login"
              autoComplete="url"
            />

            {url && (
              <button
                className="clear-button"
                type="button"
                aria-label="Clear URL"
                onClick={() => {
                  setUrl('');
                  setResult(null);
                  setError('');
                  setReported(false);
                  setReportMessage('');
                }}
              >
                ×
              </button>
            )}
          </div>

          <button
            className="scan-button"
            type="submit"
            disabled={loading || !url.trim()}
          >
            {loading ? (
              <>
                <span className="spinner" />
                Scanning
              </>
            ) : (
              <>
                <Icon name="scan" size={17} />
                Scan URL
              </>
            )}
          </button>
        </form>

        <div className="scan-note">
          <Icon name="lock" size={13} />
          URLs are analyzed by your local protection service.
        </div>

        {/* Error Message */}
        {error && (
          <div className="notice error-notice" role="alert">
            <Icon name="alert" size={17} />
            {error}
          </div>
        )}

        {/* Scan Result */}
        {result && (
          <div className={`result-card ${result.verdict}`}>
            <div className="result-topline">
              <span className={`verdict-icon ${result.verdict}`}>
                <Icon
                  name={result.verdict === 'phishing' ? 'alert' : 'check'}
                  size={20}
                />
              </span>

              <div className="result-title">
                <span className="eyebrow">
                  {result.verdict === 'phishing'
                    ? 'THREAT DETECTED'
                    : 'NO THREAT DETECTED'}
                </span>

                <h3>
                  {result.verdict === 'phishing'
                    ? 'Potential phishing link'
                    : 'Appears legitimate'}
                </h3>
              </div>

              <div className="confidence">
                <strong>
                  {(result.confidence * 100).toFixed(1)}%
                </strong>
                <span>CONFIDENCE</span>
              </div>
            </div>

            <div className="result-details">
              <div>
                <span>SCANNED URL</span>
                <strong title={result.url}>{result.url}</strong>
              </div>

              <div>
                <span>ANALYSIS ROUTE</span>
                <strong>{stageLabel(result.stage_used)}</strong>
              </div>
            </div>

            {result.reasons && result.reasons.length > 0 && (
              <div className="reasons">
                <p>Why:</p>
                <ul>
                  {result.reasons.map((reason, index) => (
                    <li key={index}>{reason}</li>
                  ))}
                </ul>
              </div>
            )}

            {result.verdict === 'phishing' && (
              <button
                className="report-button"
                onClick={report}
                disabled={reporting || reported}
              >
                <Icon
                  name={reported ? 'check' : 'alert'}
                  size={15}
                />

                {reporting
                  ? 'Submitting report…'
                  : reported
                    ? 'Domain reported'
                    : 'Report as suspected phishing'}
              </button>
            )}

            {reportMessage && (
              <div
                className="notice success-notice"
                role="status"
              >
                <Icon name="check" size={16} />
                {reportMessage}
              </div>
            )}
          </div>
        )}
      </section>

      {/* How It Works */}
      <section className="how-section">
        <div className="section-heading">
          <div>
            <span className="eyebrow">LAYERED DEFENCE</span>
            <h2>How Sentinel protects you</h2>
          </div>

          <span className="section-aside">
            TWO-STAGE DETECTION
          </span>
        </div>

        <div className="defence-grid">
          <article className="defence-card">
            <div className="defence-number">01</div>
            <div className="defence-icon">
              <Icon name="scan" size={20} />
            </div>
            <h3>Rapid screening</h3>
            <p>
              Every URL is checked for suspicious lexical patterns
              and domain signals.
            </p>
            <span className="defence-tag">
              STAGE 1 · FAST PATH
            </span>
          </article>

          <article className="defence-card">
            <div className="defence-number">02</div>
            <div className="defence-icon">
              <Icon name="shield" size={20} />
            </div>
            <h3>Deeper analysis</h3>
            <p>
              Uncertain links are escalated to a second model for
              additional scrutiny.
            </p>
            <span className="defence-tag">
              STAGE 2 · CASCADE
            </span>
          </article>

          <article className="defence-card">
            <div className="defence-number">03</div>
            <div className="defence-icon">
              <Icon name="alert" size={20} />
            </div>
            <h3>Community reports</h3>
            <p>
              Flag suspicious domains to contribute to the local
              reporting dashboard.
            </p>
            <span className="defence-tag">
              SHARED AWARENESS
            </span>
          </article>
        </div>
      </section>
    </>
  );
}

function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    request<Stats>('/stats')
      .then((data) => {
        if (active) {
          setStats(data);
          setError('');
        }
      })
      .catch((requestError: unknown) => {
        if (active) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load threat data.'
          );
        }
      })
      .finally(() => {
        if (active) {
          setLoading(false);
        }
      });

    return () => {
      active = false;
    };
  }, [refreshKey]);

  const refreshStats = () => {
    setLoading(true);
    setError('');
    setRefreshKey((key) => key + 1);
  };

  return (
    <>
      <section className="dashboard-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            SECURITY OPERATIONS
          </div>

          <h1>Threat overview</h1>

          <p>
            Monitor scan activity and community-reported domains.
          </p>
        </div>

        <button
          className="refresh-button"
          onClick={refreshStats}
          disabled={loading}
        >
          <Icon name="refresh" size={16} />
          Refresh data
        </button>
      </section>

      {error && (
        <div className="notice error-notice" role="alert">
          <Icon name="alert" size={17} />
          {error}
          <button className="inline-retry" onClick={refreshStats}>
            Retry
          </button>
        </div>
      )}

      <section className="stats-grid" aria-label="Security statistics">
        <StatCard
          icon="scan"
          label="Total scans"
          value={stats?.total_scans}
          loading={loading && !stats}
          detail="URLs analyzed"
        />

        <StatCard
          icon="alert"
          label="Threats detected"
          value={stats?.phishing_blocked}
          loading={loading && !stats}
          detail="Flagged as phishing"
          danger
        />

        <StatCard
          icon="link"
          label="Recent activity"
          value={stats?.recent.length}
          loading={loading && !stats}
          detail="Scans in latest feed"
        />
      </section>

      <div className="dashboard-grid">
        <section className="data-panel recent-panel">
          <div className="data-panel-heading">
            <div>
              <span className="eyebrow">LATEST ACTIVITY</span>
              <h2>Recent scans</h2>
            </div>

            <span className="feed-count">
              {stats?.recent.length ?? 0} / 10
            </span>
          </div>

          {loading && !stats ? (
            <div className="empty-state">
              <span className="spinner dark-spinner" />
              Loading scan activity…
            </div>
          ) : stats?.recent.length ? (
            <div className="scan-list">
              {stats.recent.map((scan, index) => (
                <div
                  className="scan-row"
                  key={`${scan.ts}-${index}`}
                >
                  <span className={`scan-status ${scan.verdict}`}>
                    <Icon
                      name={
                        scan.verdict === 'phishing'
                          ? 'alert'
                          : 'check'
                      }
                      size={15}
                    />
                  </span>

                  <div className="scan-url">
                    <strong title={scan.url}>{scan.url}</strong>
                    <span>
                      <Icon name="clock" size={12} />
                      {formatTimestamp(scan.ts)}
                    </span>
                  </div>

                  <span className={`badge ${scan.verdict}`}>
                    {scan.verdict === 'phishing'
                      ? 'PHISHING'
                      : 'LEGITIMATE'}
                  </span>

                  <span className="scan-confidence">
                    {(scan.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="scan" size={21} />
              No scans yet. Check a URL to start building activity.
            </div>
          )}
        </section>

        <section className="data-panel reports-panel">
          <div className="data-panel-heading">
            <div>
              <span className="eyebrow">COMMUNITY SIGNAL</span>
              <h2>Top reported domains</h2>
            </div>

            <span className="report-icon">
              <Icon name="alert" size={17} />
            </span>
          </div>

          {loading && !stats ? (
            <div className="empty-state">
              <span className="spinner dark-spinner" />
              Loading reports…
            </div>
          ) : stats?.top_reported.length ? (
            <div className="report-list">
              {stats.top_reported.map((report, index) => (
                <div className="report-row" key={report.domain}>
                  <span className="report-rank">
                    {String(index + 1).padStart(2, '0')}
                  </span>

                  <span className="report-domain">
                    {report.domain}
                  </span>

                  <span className="report-count">
                    {report.count}{' '}
                    {report.count === 1 ? 'report' : 'reports'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              <Icon name="check" size={21} />
              No community reports yet.
            </div>
          )}

          <div className="report-footnote">
            Reports are collected by this local backend.
          </div>
        </section>
      </div>

      <section className="dashboard-tip">
        <div className="tip-icon">
          <Icon name="shield" size={19} />
        </div>

        <div>
          <strong>Stay alert, stay protected.</strong>
          <p>
            Double-check the spelling of a domain and avoid entering
            credentials on links you weren’t expecting.
          </p>
        </div>

        <Icon name="arrow" size={17} />
      </section>
    </>
  );
}

function StatCard({
  icon,
  label,
  value,
  loading,
  detail,
  danger = false,
}: {
  icon: string;
  label: string;
  value?: number;
  loading: boolean;
  detail: string;
  danger?: boolean;
}) {
  return (
    <article className={`stat-card ${danger ? 'danger' : ''}`}>
      <div className="stat-card-top">
        <span>{label}</span>
        <span className="stat-icon">
          <Icon name={icon} size={18} />
        </span>
      </div>

      <div className="stat-value">
        {loading ? (
          <span className="value-skeleton" />
        ) : (
          (value ?? 0).toLocaleString()
        )}
      </div>

      <div className="stat-detail">
        <span className="stat-detail-dot" />
        {detail}
      </div>
    </article>
  );
}

function formatTimestamp(value: string) {
  const date = new Date(
    value.endsWith('Z') ? value : `${value}Z`
  );

  if (Number.isNaN(date.getTime())) {
    return 'Time unavailable';
  }

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}
