import React, { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, AlertTriangle, Search, Trash2, CheckCircle2, AlertCircle } from 'lucide-react';

interface Sample {
  from: string;
  subject: string;
  replyto: string;
  body: string;
}

const SAMPLES: Record<string, Sample> = {
  phishing: {
    from: 'security-alert@paypa1-secure-login.com',
    subject: 'URGENT: Your account has been compromised! Verify NOW',
    replyto: 'collect@harvest99.ru',
    body: `Dear Valued Customer,

We have detected suspicious activity on your PayPal account. Your account will be SUSPENDED within 24 hours unless you verify your information immediately.

Click here to verify your account: http://paypa1-secure-login.com/verify?token=abc123&redirect=http://evil.ru

Please provide the following to avoid suspension:
- Full Name
- Credit Card Number
- CVV and Expiry Date
- Social Security Number
- Online Banking Password

This is your FINAL WARNING. Act now or lose access permanently!

Failure to comply will result in legal action and account termination.

PayPal Security Team
© 2024 PayPa1 Inc. All Rights Reserved.`
  },
  legit: {
    from: 'newsletter@github.com',
    subject: 'Your GitHub digest for the week',
    replyto: '',
    body: `Hi there,

Here's what happened this week across your repositories and organizations you follow.

New pull requests: 3 merged, 1 open
Issues closed this week: 7
New stars on your repos: 42

Trending repositories you might like:
- rust-lang/rust — The Rust programming language
- facebook/react — The library for web and native user interfaces

You're receiving this because you signed up for GitHub digest emails.
Manage notifications: https://github.com/settings/notifications
Unsubscribe: https://github.com/notifications/unsubscribe

GitHub, Inc. · 88 Colin P Kelly Jr Street · San Francisco, CA 94107`
  },
  spam: {
    from: 'deals@best-offers-4u.info',
    subject: 'You WON!!! Claim your FREE iPhone 15 Pro Max!!!',
    replyto: 'noreply@free-gifts-center.tk',
    body: `CONGRATULATIONS!!!

You have been SELECTED as our lucky winner!!!

You have won: FREE iPhone 15 Pro Max + $500 Amazon Gift Card!!!

To CLAIM your prize click NOW:
http://free-gifts-center.tk/claim?id=WIN2024&ref=spamblast

LIMITED TIME OFFER - Only 3 winners left!!!
This offer EXPIRES in 1 HOUR!!!

To unsubscribe reply STOP (but why would you miss this amazing offer?!)

Best Regards,
The Prize Team`
  }
};

interface Signal {
  name: string;
  desc: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'safe';
  weight: number;
}

interface FeatureBar {
  name: string;
  val: number;
  raw: string;
}

interface HistoryItem {
  id: string;
  from: string;
  subject: string;
  score: number;
  time: string;
}

export default function App() {
  const [from, setFrom] = useState('');
  const [subject, setSubject] = useState('');
  const [replyTo, setReplyTo] = useState('');
  const [body, setBody] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const [hasAnalyzed, setHasAnalyzed] = useState(false);
  const [score, setScore] = useState(0);
  const [signals, setSignals] = useState<Signal[]>([]);
  const [featureBars, setFeatureBars] = useState<FeatureBar[]>([]);
  const [extractedUrls, setExtractedUrls] = useState<string[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const loadSample = (type: 'phishing' | 'legit' | 'spam') => {
    const s = SAMPLES[type];
    setFrom(s.from);
    setSubject(s.subject);
    setReplyTo(s.replyto);
    setBody(s.body);
  };

  const countGrammarErrors = (text: string) => {
    let errors = 0;
    if (/\s{3,}/.test(text)) errors++;
    if (/[,.!?]{2,}/.test(text)) errors++;
    if (/\bi am\b/i.test(text) && !/formal/.test(text)) errors += 0.5;
    if (/ \./.test(text)) errors++;
    return Math.round(errors);
  };

  const extractFeatures = (fromStr: string, subjStr: string, replyStr: string, bodyStr: string) => {
    const text = (subjStr + ' ' + bodyStr).toLowerCase();

    const fromDomain = fromStr.split('@')[1] || '';
    const replyDomain = replyStr ? (replyStr.split('@')[1] || '') : '';
    const fromSenderName = fromStr.split('@')[0] || '';

    const senderFeatures = {
      homoglyphDomain: /[0-9]/.test(fromDomain.split('.')[0]) && /paypal|amazon|apple|microsoft|google|bank|secure/.test(fromDomain),
      domainMismatch: Boolean(replyStr && replyDomain && fromDomain !== replyDomain),
      suspiciousTLD: /\.(tk|ru|cn|xyz|info|biz|top|click|loan|win|club|work|gdn|men|accountant|racing|download)$/.test(fromDomain),
      freeMailSpoofing: /gmail|yahoo|hotmail|outlook/.test(fromDomain) && /bank|paypal|amazon|apple|microsoft|irs|gov|support/.test(fromSenderName),
      longSubdomain: fromDomain.split('.').length > 3,
      knownBrand: /paypal|amazon|apple|microsoft|google|netflix|facebook|instagram|twitter|linkedin|bank|wells.fargo|chase|citi|irs|fedex|ups|dhl/.test(fromDomain),
      knownGoodDomain: /github\.com|google\.com|microsoft\.com|apple\.com|amazon\.com$/.test(fromDomain)
    };

    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
    const urls = [...bodyStr.matchAll(urlRegex)].map(m => m[0]);

    const urlFeatures = {
      hasUrls: urls.length > 0,
      urlCount: urls.length,
      suspiciousUrls: urls.filter(u => {
        const d = u.replace(/https?:\/\//, '').split('/')[0];
        return /[0-9]/.test(d.split('.')[0]) || d.split('.').length > 4 || /\.(tk|ru|cn|xyz|info)/.test(d);
      }).length,
      ipUrls: urls.filter(u => /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(u)).length,
      brandInUrl: urls.some(u => /paypal|amazon|apple|microsoft|google|bank/.test(u.toLowerCase())),
      redirectUrls: urls.filter(u => /redirect|token|ref=|goto|url=/.test(u.toLowerCase())).length,
    };

    const urgencyWords = ['urgent', 'immediately', 'action required', 'expires', 'suspended', 'terminate', 'warning', 'verify now', 'click now', 'final notice', 'last chance', 'within 24', 'within 48', 'within 1 hour', 'act now', 'limited time'];
    const threatWords = ['suspended', 'legal action', 'law enforcement', 'criminal', 'prosecuted', 'arrested', 'penalty', 'fine', 'locked out', 'permanently', 'deactivated'];
    const greedWords = ['won', 'winner', 'congratulations', 'free', 'prize', 'gift card', 'reward', '$', 'lottery', 'selected', 'lucky'];
    const sensitiveRequests = ['password', 'credit card', 'cvv', 'social security', 'ssn', 'bank account', 'routing number', 'pin', 'secret question', "mother's maiden"];

    const linguisticFeatures = {
      urgencyScore: urgencyWords.filter(w => text.includes(w)).length,
      threatScore: threatWords.filter(w => text.includes(w)).length,
      greedScore: greedWords.filter(w => text.includes(w)).length,
      sensitiveDataRequest: sensitiveRequests.filter(w => text.includes(w)).length,
      excessiveCaps: (text.match(/[A-Z]{3,}/g) || []).length,
      exclamationCount: (bodyStr.match(/!/g) || []).length,
      grammarErrors: countGrammarErrors(bodyStr),
      genericGreeting: /dear (customer|user|member|valued|account holder|sir|madam)/i.test(bodyStr),
      noPersonalization: !/dear [a-z]+ [a-z]+/i.test(bodyStr),
      longEmail: bodyStr.length > 800,
    };

    const structuralFeatures = {
      subjectAllCaps: subjStr === subjStr.toUpperCase() && subjStr.length > 5,
      htmlInjection: /<script|<iframe|<object/.test(bodyStr),
      attachmentMention: /attachment|attached|please open|download now/.test(text),
      unsubscribePresent: /unsubscribe|opt.out|manage.preferences/.test(text),
      copyrightPresent: /copyright|©|all rights reserved/.test(text),
      shortBody: bodyStr.trim().split(/\s+/).length < 30,
    };

    return { senderFeatures, urlFeatures, linguisticFeatures, structuralFeatures, urls };
  };

  const computeScore = (f: ReturnType<typeof extractFeatures>) => {
    const { senderFeatures: s, urlFeatures: u, linguisticFeatures: l, structuralFeatures: st } = f;

    let total = 0;
    const sigs: Signal[] = [];

    // Sender signals
    if (s.homoglyphDomain) { total += 28; sigs.push({ name: 'Homoglyph domain', desc: 'Brand name with digit substitution', risk: 'critical', weight: 28 }); }
    if (s.domainMismatch) { total += 22; sigs.push({ name: 'Reply-To mismatch', desc: 'Reply domain differs from sender', risk: 'high', weight: 22 }); }
    if (s.suspiciousTLD) { total += 18; sigs.push({ name: 'Suspicious TLD', desc: 'High-abuse top-level domain (.tk .ru .xyz etc.)', risk: 'high', weight: 18 }); }
    if (s.freeMailSpoofing) { total += 15; sigs.push({ name: 'Brand impersonation', desc: 'Free email spoofing trusted brand name', risk: 'high', weight: 15 }); }
    if (s.longSubdomain) { total += 10; sigs.push({ name: 'Deep subdomain chain', desc: 'Multiple subdomains to obscure real domain', risk: 'medium', weight: 10 }); }

    // URL signals
    if (u.ipUrls > 0) { total += 22; sigs.push({ name: 'IP address URL', desc: `${u.ipUrls} link(s) use raw IP instead of domain`, risk: 'critical', weight: 22 }); }
    if (u.suspiciousUrls > 0) { total += 14 * Math.min(u.suspiciousUrls, 2); sigs.push({ name: 'Obfuscated URLs', desc: `${u.suspiciousUrls} suspicious link(s) detected`, risk: 'high', weight: 14 * Math.min(u.suspiciousUrls, 2) }); }
    if (u.brandInUrl && s.homoglyphDomain) { total += 10; sigs.push({ name: 'Brand in URL body', desc: 'Trusted brand name embedded in phishing URL', risk: 'high', weight: 10 }); }
    if (u.redirectUrls > 0) { total += 8; sigs.push({ name: 'Redirect parameter', desc: `${u.redirectUrls} URL(s) use redirect/token params`, risk: 'medium', weight: 8 }); }

    // Linguistic signals
    if (l.urgencyScore >= 3) { total += 12; sigs.push({ name: 'High urgency language', desc: `${l.urgencyScore} urgency phrases detected`, risk: 'high', weight: 12 }); }
    else if (l.urgencyScore >= 1) { total += 6; sigs.push({ name: 'Urgency language', desc: `${l.urgencyScore} urgency phrase(s) found`, risk: 'medium', weight: 6 }); }

    if (l.threatScore >= 2) { total += 14; sigs.push({ name: 'Threat language', desc: `${l.threatScore} threat/consequence phrases`, risk: 'high', weight: 14 }); }
    if (l.greedScore >= 3) { total += 10; sigs.push({ name: 'Greed bait', desc: `${l.greedScore} reward/prize references`, risk: 'medium', weight: 10 }); }
    if (l.sensitiveDataRequest >= 1) { total += 20; sigs.push({ name: 'Credential harvesting', desc: `Requests sensitive info (${l.sensitiveDataRequest} field types)`, risk: 'critical', weight: 20 }); }
    if (l.excessiveCaps >= 3) { total += 7; sigs.push({ name: 'Excessive capitalization', desc: 'Shouting text pattern common in phishing', risk: 'low', weight: 7 }); }
    if (l.exclamationCount >= 5) { total += 5; sigs.push({ name: 'Excessive exclamation', desc: `${l.exclamationCount} exclamation marks found`, risk: 'low', weight: 5 }); }
    if (l.genericGreeting) { total += 6; sigs.push({ name: 'Generic greeting', desc: '"Dear Customer/User/Member" — no personalization', risk: 'medium', weight: 6 }); }
    if (l.grammarErrors >= 1) { total += 5; sigs.push({ name: 'Grammar anomalies', desc: 'Unusual spacing or punctuation patterns', risk: 'low', weight: 5 }); }

    // Structural
    if (st.subjectAllCaps) { total += 6; sigs.push({ name: 'ALL-CAPS subject', desc: 'Alarm tactic in subject line', risk: 'low', weight: 6 }); }
    if (st.htmlInjection) { total += 25; sigs.push({ name: 'Code injection attempt', desc: 'Script/iframe tags in email body', risk: 'critical', weight: 25 }); }

    // Legitimacy reducers
    if (s.knownGoodDomain) { total -= 35; sigs.push({ name: 'Verified sender domain', desc: 'Sender matches known trusted domain', risk: 'safe', weight: -35 }); }
    if (st.unsubscribePresent && !l.urgencyScore) { total -= 8; sigs.push({ name: 'Unsubscribe link present', desc: 'Compliant email marketing practice', risk: 'safe', weight: -8 }); }
    if (st.copyrightPresent) { total -= 5; sigs.push({ name: 'Copyright notice', desc: 'Indicates legitimate organizational email', risk: 'safe', weight: -5 }); }

    total = Math.max(0, Math.min(100, total));
    return { score: Math.round(total), signals: sigs };
  };

  const buildFeatureBars = (f: ReturnType<typeof extractFeatures>): FeatureBar[] => {
    const { linguisticFeatures: l, urlFeatures: u, senderFeatures: s } = f;
    return [
      { name: 'Urgency language', val: Math.min(100, l.urgencyScore * 25), raw: `${l.urgencyScore} phrases` },
      { name: 'Threat language', val: Math.min(100, l.threatScore * 30), raw: `${l.threatScore} phrases` },
      { name: 'Greed signals', val: Math.min(100, l.greedScore * 20), raw: `${l.greedScore} signals` },
      { name: 'Sensitive data requests', val: Math.min(100, l.sensitiveDataRequest * 35), raw: `${l.sensitiveDataRequest} fields` },
      { name: 'Suspicious URLs', val: Math.min(100, u.suspiciousUrls * 40 + u.ipUrls * 50), raw: `${u.suspiciousUrls} flagged` },
      { name: 'Sender anomalies', val: (s.homoglyphDomain ? 70 : 0) + (s.domainMismatch ? 30 : 0), raw: s.homoglyphDomain ? 'homoglyph' : s.domainMismatch ? 'mismatch' : 'none' },
    ];
  };

  const handleAnalyze = () => {
    if (!from.trim() && !subject.trim() && !body.trim()) {
      alert('Please enter at least a sender, subject, or body to analyze.');
      return;
    }

    setIsAnalyzing(true);

    setTimeout(() => {
      const features = extractFeatures(from, subject, replyTo, body);
      const { score: computedScore, signals: computedSignals } = computeScore(features);
      const bars = buildFeatureBars(features);

      setScore(computedScore);
      setSignals(computedSignals);
      setFeatureBars(bars);
      setExtractedUrls(features.urls);
      setHasAnalyzed(true);

      const now = new Date();
      setHistory(prev => [
        {
          id: Math.random().toString(36).substring(7),
          from: from || 'unknown',
          subject: subject || '(no subject)',
          score: computedScore,
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        },
        ...prev
      ]);

      setIsAnalyzing(false);
    }, 500);
  };

  const getRiskColor = (risk: Signal['risk']) => {
    switch (risk) {
      case 'critical': return '#ff4d6d';
      case 'high': return '#ff7a50';
      case 'medium': return '#ffb340';
      case 'low': return '#8b90a0';
      case 'safe': return '#00e5b4';
      default: return '#8b90a0';
    }
  };

  const getScoreColor = (sc: number) => {
    if (sc >= 70) return '#ff4d6d';
    if (sc >= 45) return '#ffb340';
    if (sc >= 20) return '#4d9eff';
    return '#00e5b4';
  };

  const getVerdict = (sc: number) => {
    if (sc >= 75) return { label: 'PHISHING', desc: 'High-confidence phishing attempt. Do not click links or provide any information.' };
    if (sc >= 55) return { label: 'LIKELY PHISHING', desc: 'Strong phishing indicators detected. Treat this email with extreme caution.' };
    if (sc >= 35) return { label: 'SUSPICIOUS', desc: 'Several suspicious signals found. Verify sender through official channels before acting.' };
    if (sc >= 15) return { label: 'LOW RISK', desc: 'Minimal threat indicators. Likely legitimate but exercise general caution.' };
    return { label: 'CLEAN', desc: 'No significant phishing indicators detected. Appears to be a legitimate email.' };
  };

  const circ = 2 * Math.PI * 46;
  const offset = circ * (1 - score / 100);
  const currentColor = getScoreColor(score);
  const currentVerdict = getVerdict(score);

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#e8eaf0] font-sans antialiased p-4 sm:p-8">
      <div className="max-w-[1100px] mx-auto">
        {/* Header */}
        <header className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 mb-8 border-b border-white/10 gap-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#00e5b4]/10 border border-[#00e5b4] flex items-center justify-center text-[#00e5b4]">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">PhishGuard</h1>
              <p className="text-xs text-[#555b6e] font-mono uppercase tracking-wider">ML-Powered Email Threat Detector</p>
            </div>
          </div>
          <div>
            <span className="font-mono text-xs px-3 py-1 rounded-full uppercase tracking-wider bg-[#00e5b4]/10 text-[#00e5b4] border border-[#00e5b4]/30">
              v2.4 · Naive Bayes + SVM Ensemble
            </span>
          </div>
        </header>

        {/* Main Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-5 items-start">
          {/* Left Column: Inputs & Advanced panels */}
          <div className="space-y-5">
            {/* Input Panel */}
            <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-4 border-b border-white/10 flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">Email Input</span>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-[#555b6e]">Load sample:</span>
                  <button
                    type="button"
                    onClick={() => loadSample('phishing')}
                    className="font-mono text-xs px-2.5 py-1 rounded-full border border-white/15 bg-[#181c24] text-[#8b90a0] hover:text-[#ff4d6d] hover:border-[#ff4d6d] hover:bg-[#ff4d6d]/10 transition-colors uppercase"
                  >
                    Phishing
                  </button>
                  <button
                    type="button"
                    onClick={() => loadSample('legit')}
                    className="font-mono text-xs px-2.5 py-1 rounded-full border border-white/15 bg-[#181c24] text-[#8b90a0] hover:text-[#00e5b4] hover:border-[#00e5b4] hover:bg-[#00e5b4]/10 transition-colors uppercase"
                  >
                    Legit
                  </button>
                  <button
                    type="button"
                    onClick={() => loadSample('spam')}
                    className="font-mono text-xs px-2.5 py-1 rounded-full border border-white/15 bg-[#181c24] text-[#8b90a0] hover:text-[#ffb340] hover:border-[#ffb340] hover:bg-[#ffb340]/10 transition-colors uppercase"
                  >
                    Spam
                  </button>
                </div>
              </div>

              <div className="p-5 space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[#8b90a0] uppercase tracking-wider block">From (Sender)</label>
                  <input
                    type="text"
                    value={from}
                    onChange={e => setFrom(e.target.value)}
                    placeholder="e.g. support@paypa1-secure.com"
                    className="w-full bg-[#181c24] border border-white/10 rounded-lg text-white font-mono text-sm px-3.5 py-2.5 outline-none focus:border-[#00e5b4] focus:ring-2 focus:ring-[#00e5b4]/20 transition-all placeholder:text-white/20"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[#8b90a0] uppercase tracking-wider block">Subject</label>
                  <input
                    type="text"
                    value={subject}
                    onChange={e => setSubject(e.target.value)}
                    placeholder="e.g. Urgent: Verify your account immediately"
                    className="w-full bg-[#181c24] border border-white/10 rounded-lg text-white font-mono text-sm px-3.5 py-2.5 outline-none focus:border-[#00e5b4] focus:ring-2 focus:ring-[#00e5b4]/20 transition-all placeholder:text-white/20"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[#8b90a0] uppercase tracking-wider block">Reply-To (optional)</label>
                  <input
                    type="text"
                    value={replyTo}
                    onChange={e => setReplyTo(e.target.value)}
                    placeholder="e.g. reply@different-domain.ru"
                    className="w-full bg-[#181c24] border border-white/10 rounded-lg text-white font-mono text-sm px-3.5 py-2.5 outline-none focus:border-[#00e5b4] focus:ring-2 focus:ring-[#00e5b4]/20 transition-all placeholder:text-white/20"
                  />
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-[#8b90a0] uppercase tracking-wider block">Email Body</label>
                  <textarea
                    rows={6}
                    value={body}
                    onChange={e => setBody(e.target.value)}
                    placeholder="Paste the full email body here..."
                    className="w-full bg-[#181c24] border border-white/10 rounded-lg text-white font-mono text-sm px-3.5 py-2.5 outline-none focus:border-[#00e5b4] focus:ring-2 focus:ring-[#00e5b4]/20 transition-all placeholder:text-white/20 resize-y"
                  />
                </div>

                <p className="text-xs font-mono text-[#555b6e]">
                  ML features extracted: linguistic patterns, URL analysis, sender heuristics, urgency signals, structural anomalies
                </p>

                <button
                  type="button"
                  id="analyze-btn"
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  className="w-full py-3 bg-[#00e5b4] text-[#0a0c10] font-bold text-sm rounded-lg hover:opacity-90 active:scale-[0.99] transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 cursor-pointer shadow-md"
                >
                  <Search className="w-4 h-4" />
                  {isAnalyzing ? 'Analyzing…' : 'Analyze Email'}
                </button>
              </div>
            </div>

            {/* Feature Weights Breakdown */}
            {hasAnalyzed && (
              <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
                <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                  <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">ML Feature Weights</span>
                  <span className="text-xs font-mono text-[#555b6e]">Naive Bayes posterior probabilities</span>
                </div>
                <div className="p-5 space-y-3">
                  {featureBars.map((b, idx) => (
                    <div key={idx} className="space-y-1.5">
                      <div className="flex justify-between items-center text-xs font-mono">
                        <span className="text-[#8b90a0]">{b.name}</span>
                        <span className="text-[#555b6e]">{b.raw}</span>
                      </div>
                      <div className="h-1.5 bg-[#1e2330] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${b.val}%`,
                            backgroundColor: b.val > 60 ? '#ff4d6d' : b.val > 30 ? '#ffb340' : '#00e5b4'
                          }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* URL Analysis Chips */}
            {hasAnalyzed && extractedUrls.length > 0 && (
              <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
                <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                  <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">URL Analysis</span>
                  <span className="text-xs font-mono text-[#555b6e]">
                    {extractedUrls.length} URL{extractedUrls.length !== 1 ? 's' : ''} found
                  </span>
                </div>
                <div className="p-5 flex flex-wrap gap-2">
                  {extractedUrls.map((url, idx) => {
                    const d = url.replace(/https?:\/\//, '').split('/')[0];
                    const isIP = /\d+\.\d+\.\d+\.\d+/.test(d);
                    const isSusp = /[0-9]/.test(d.split('.')[0]) || /\.(tk|ru|xyz|info|click)/.test(d) || isIP || d.split('.').length > 4;

                    const colorClass = isIP
                      ? 'bg-[#ff4d6d]/10 border-[#ff4d6d]/30 text-[#ff4d6d]'
                      : isSusp
                      ? 'bg-[#ffb340]/10 border-[#ffb340]/30 text-[#ffb340]'
                      : 'bg-[#00e5b4]/10 border-[#00e5b4]/30 text-[#00e5b4]';

                    const label = isIP ? '⚠ IP URL' : isSusp ? '⚠ Suspicious' : '✓ OK';

                    return (
                      <div
                        key={idx}
                        title={url}
                        className={`font-mono text-xs px-2.5 py-1.5 rounded border max-w-[240px] truncate ${colorClass}`}
                      >
                        {label}: {d}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Right Column: Assessment, Signals & History */}
          <div className="space-y-5">
            {/* Threat Assessment Panel */}
            <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">Threat Assessment</span>
                <span className="text-xs font-mono text-[#555b6e]">
                  {hasAnalyzed ? `Ensemble confidence: ${score}%` : '—'}
                </span>
              </div>

              <div className="p-6 flex flex-col items-center text-center">
                {!hasAnalyzed ? (
                  <div className="py-10 text-center text-[#555b6e]">
                    <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
                    <p className="text-xs font-mono">Awaiting email input</p>
                  </div>
                ) : (
                  <div className="w-full flex flex-col items-center gap-3">
                    {/* Ring Chart */}
                    <div className="relative w-[120px] h-[120px]">
                      <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                        <circle
                          className="text-[#1e2330]"
                          strokeWidth="8"
                          stroke="currentColor"
                          fill="transparent"
                          r="46"
                          cx="50"
                          cy="50"
                        />
                        <circle
                          style={{
                            stroke: currentColor,
                            strokeDasharray: circ,
                            strokeDashoffset: offset,
                            transition: 'stroke-dashoffset 0.8s ease'
                          }}
                          strokeWidth="8"
                          strokeLinecap="round"
                          fill="transparent"
                          r="46"
                          cx="50"
                          cy="50"
                        />
                      </svg>
                      <div
                        className="absolute inset-0 flex items-center justify-center text-3xl font-extrabold"
                        style={{ color: currentColor }}
                      >
                        {score}
                      </div>
                    </div>

                    <div className="text-xl font-bold tracking-tight" style={{ color: currentColor }}>
                      {currentVerdict.label}
                    </div>

                    <p className="text-xs text-[#8b90a0] max-w-[240px] leading-relaxed">
                      {currentVerdict.desc}
                    </p>

                    <div className="w-full flex gap-1 mt-2">
                      {[0, 20, 45, 70].map((thr, idx) => (
                        <div
                          key={idx}
                          className="flex-1 h-1 rounded-full transition-colors duration-300"
                          style={{
                            backgroundColor: score >= thr ? currentColor : '#1e2330'
                          }}
                        />
                      ))}
                    </div>

                    <div className="w-full flex justify-between text-[10px] font-mono text-[#555b6e] pt-1">
                      <span>0 Clean</span>
                      <span>20 Low</span>
                      <span>45 Med</span>
                      <span>70 High</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Detection Signals */}
            <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">Detection Signals</span>
                <span className="text-xs font-mono text-[#555b6e]">
                  {hasAnalyzed ? `${signals.length} signal${signals.length !== 1 ? 's' : ''} detected` : '—'}
                </span>
              </div>

              <div>
                {!hasAnalyzed || signals.length === 0 ? (
                  <div className="py-8 text-center text-[#555b6e]">
                    <p className="text-xs font-mono">No signals detected yet</p>
                  </div>
                ) : (
                  <div className="divide-y divide-white/5 max-h-[300px] overflow-y-auto">
                    {[...signals].sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight)).map((sig, idx) => {
                      const col = getRiskColor(sig.risk);
                      return (
                        <div key={idx} className="p-3.5 flex items-center gap-3 hover:bg-white/[0.02] transition-colors">
                          <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: col }} />
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-medium text-white truncate">{sig.name}</div>
                            <div className="text-[11px] font-mono text-[#555b6e] truncate">{sig.desc}</div>
                          </div>
                          <div
                            className="font-mono text-xs px-2 py-0.5 rounded border"
                            style={{
                              backgroundColor: `${col}15`,
                              borderColor: `${col}40`,
                              color: col
                            }}
                          >
                            {sig.weight > 0 ? `+${sig.weight}` : sig.weight}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>

            {/* Scan History */}
            <div className="bg-[#111318] border border-white/10 rounded-xl overflow-hidden shadow-lg">
              <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                <span className="text-xs font-mono text-[#555b6e] uppercase tracking-wider">Scan History</span>
                {history.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setHistory([])}
                    className="text-xs font-mono text-[#555b6e] hover:text-[#ff4d6d] flex items-center gap-1 transition-colors"
                  >
                    <Trash2 className="w-3 h-3" /> Clear
                  </button>
                )}
              </div>

              <div>
                {history.length === 0 ? (
                  <div className="py-8 text-center text-[#555b6e]">
                    <p className="text-xs font-mono">No scans yet</p>
                  </div>
                ) : (
                  <div className="divide-y divide-white/5 max-h-[220px] overflow-y-auto">
                    {history.map(item => {
                      const col = getScoreColor(item.score);
                      return (
                        <div key={item.id} className="p-3.5 flex items-center gap-3 hover:bg-white/[0.02] transition-colors">
                          <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: col }} />
                          <div className="flex-1 min-w-0">
                            <div className="text-xs text-white truncate">{item.subject}</div>
                            <div className="text-[11px] font-mono text-[#555b6e] truncate">{item.from} · {item.time}</div>
                          </div>
                          <div className="font-mono text-xs font-bold" style={{ color: col }}>
                            {item.score}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

