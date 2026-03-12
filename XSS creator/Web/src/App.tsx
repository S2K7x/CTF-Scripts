import { useState, useMemo, useCallback } from 'react';
import {
  buildPayloads,
  applyContextBreakers,
  generateWordlistContent,
  ALL_CATEGORIES,
  CATEGORY_INFO,
  CONTEXT_BREAKERS,
  type CategoryName,
  type Payload,
} from './payloadEngine';

function App() {
  // ── State ──────────────────────────────────────────────────────────────────
  const [ip, setIp] = useState('http://YOUR_IP_HERE');
  const [selectedCategories, setSelectedCategories] = useState<CategoryName[]>([...ALL_CATEGORIES]);
  const [selectedBreakers, setSelectedBreakers] = useState<string[]>([]);
  const [breakerMode, setBreakerMode] = useState<'prefix' | 'suffix' | 'both' | 'combo'>('prefix');
  const [includeComments, setIncludeComments] = useState(true);
  const [searchFilter, setSearchFilter] = useState('');
  const [expandedCat, setExpandedCat] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [customBreaker, setCustomBreaker] = useState('');
  const [customBreakers, setCustomBreakers] = useState<{ id: string; char: string; label: string; description: string }[]>([]);

  // ── Build payloads ─────────────────────────────────────────────────────────
  const allCategorized = useMemo(() => buildPayloads(ip), [ip]);

  const selectedPayloads = useMemo(() => {
    const payloads: Payload[] = [];
    for (const cat of selectedCategories) {
      if (allCategorized[cat]) {
        payloads.push(...allCategorized[cat]);
      }
    }
    return payloads;
  }, [allCategorized, selectedCategories]);

  const allBreakers = useMemo(() => [...CONTEXT_BREAKERS, ...customBreakers], [customBreakers]);

  const finalPayloads = useMemo(() => {
    return applyContextBreakers(selectedPayloads, selectedBreakers, breakerMode);
  }, [selectedPayloads, selectedBreakers, breakerMode]);

  const filteredPayloads = useMemo(() => {
    if (!searchFilter) return finalPayloads;
    const lower = searchFilter.toLowerCase();
    return finalPayloads.filter(
      p =>
        p.pid.toLowerCase().includes(lower) ||
        p.description.toLowerCase().includes(lower) ||
        p.payload.toLowerCase().includes(lower) ||
        p.category.toLowerCase().includes(lower)
    );
  }, [finalPayloads, searchFilter]);

  const wordlistContent = useMemo(() => {
    return generateWordlistContent(finalPayloads, ip, selectedCategories, includeComments);
  }, [finalPayloads, ip, selectedCategories, includeComments]);

  // ── Handlers ───────────────────────────────────────────────────────────────
  const toggleCategory = useCallback((cat: CategoryName) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    );
  }, []);

  const selectAllCategories = useCallback(() => setSelectedCategories([...ALL_CATEGORIES]), []);
  const deselectAllCategories = useCallback(() => setSelectedCategories([]), []);

  const toggleBreaker = useCallback((id: string) => {
    setSelectedBreakers(prev =>
      prev.includes(id) ? prev.filter(b => b !== id) : [...prev, id]
    );
  }, []);

  const selectAllBreakers = useCallback(() => {
    setSelectedBreakers(allBreakers.map(b => b.id));
  }, [allBreakers]);

  const deselectAllBreakers = useCallback(() => setSelectedBreakers([]), []);

  const addCustomBreaker = useCallback(() => {
    if (!customBreaker.trim()) return;
    const id = `custom-${Date.now()}`;
    setCustomBreakers(prev => [
      ...prev,
      { id, char: customBreaker, label: customBreaker, description: `Custom context breaker: ${customBreaker}` },
    ]);
    setSelectedBreakers(prev => [...prev, id]);
    setCustomBreaker('');
  }, [customBreaker]);

  const removeCustomBreaker = useCallback((id: string) => {
    setCustomBreakers(prev => prev.filter(b => b.id !== id));
    setSelectedBreakers(prev => prev.filter(b => b !== id));
  }, []);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(wordlistContent).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, [wordlistContent]);

  const handleDownload = useCallback(() => {
    const blob = new Blob([wordlistContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'blind_xss_wordlist.txt';
    a.click();
    URL.revokeObjectURL(url);
  }, [wordlistContent]);

  const stats = useMemo(() => {
    const catCounts: Record<string, number> = {};
    for (const p of finalPayloads) {
      catCounts[p.category] = (catCounts[p.category] || 0) + 1;
    }
    return {
      total: finalPayloads.length,
      originalCount: selectedPayloads.length,
      withBreakers: finalPayloads.length - selectedPayloads.length,
      catCounts,
    };
  }, [finalPayloads, selectedPayloads]);

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-[#0a0a0f] text-gray-100">
      {/* Header */}
      <header className="border-b border-gray-800 bg-[#0d0d14]">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center gap-4">
            <div className="text-4xl">💉</div>
            <div>
              <h1 className="text-2xl font-bold bg-gradient-to-r from-red-500 via-orange-400 to-yellow-400 bg-clip-text text-transparent">
                Blind XSS Payload Generator
              </h1>
              <p className="text-sm text-gray-500 mt-1">
                Génère des wordlists avec ID unique par payload • Context breakers • Export one-click
              </p>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6 space-y-6">
        {/* Stats bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <StatCard label="Total Payloads" value={stats.total} color="text-red-400" />
          <StatCard label="Payloads Originaux" value={stats.originalCount} color="text-blue-400" />
          <StatCard label="Avec Context Breakers" value={stats.withBreakers} color="text-orange-400" />
          <StatCard label="Catégories" value={selectedCategories.length} color="text-green-400" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left column - Configuration */}
          <div className="lg:col-span-1 space-y-4">
            {/* IP Config */}
            <Section title="🎯 Callback IP / URL" defaultOpen>
              <input
                type="text"
                value={ip}
                onChange={e => setIp(e.target.value)}
                placeholder="http://YOUR_IP:PORT"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm font-mono text-green-400 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/30"
              />
              <p className="text-xs text-gray-600 mt-1">
                Ex: http://10.10.14.1:8080 ou https://abc.burpcollaborator.net
              </p>
            </Section>

            {/* Categories */}
            <Section title="📂 Catégories" defaultOpen>
              <div className="flex gap-2 mb-3">
                <button
                  onClick={selectAllCategories}
                  className="text-xs px-2 py-1 bg-green-900/40 text-green-400 rounded hover:bg-green-900/60 transition-colors"
                >
                  Tout
                </button>
                <button
                  onClick={deselectAllCategories}
                  className="text-xs px-2 py-1 bg-red-900/40 text-red-400 rounded hover:bg-red-900/60 transition-colors"
                >
                  Rien
                </button>
              </div>
              <div className="space-y-1">
                {ALL_CATEGORIES.map(cat => {
                  const info = CATEGORY_INFO[cat];
                  const isSelected = selectedCategories.includes(cat);
                  const count = allCategorized[cat]?.length || 0;
                  return (
                    <button
                      key={cat}
                      onClick={() => toggleCategory(cat)}
                      className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg text-left text-sm transition-all ${
                        isSelected
                          ? 'bg-red-900/30 border border-red-800/50 text-gray-100'
                          : 'bg-gray-900/50 border border-gray-800/50 text-gray-500 hover:text-gray-300'
                      }`}
                    >
                      <span className="text-base">{info.icon}</span>
                      <span className="flex-1 font-medium">{info.label}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded ${isSelected ? 'bg-red-900/50 text-red-300' : 'bg-gray-800 text-gray-600'}`}>
                        {count}
                      </span>
                      <div className={`w-3 h-3 rounded-sm border ${isSelected ? 'bg-red-500 border-red-500' : 'border-gray-600'}`}>
                        {isSelected && <CheckIcon />}
                      </div>
                    </button>
                  );
                })}
              </div>
            </Section>

            {/* Context Breakers */}
            <Section title="🔓 Context Breakers" defaultOpen>
              <p className="text-xs text-gray-500 mb-3">
                Ajouter des caractères avant/après chaque payload pour sortir du contexte d'injection
              </p>

              {/* Mode selector */}
              <div className="grid grid-cols-2 gap-1.5 mb-3">
                {(['prefix', 'suffix', 'both', 'combo'] as const).map(mode => (
                  <button
                    key={mode}
                    onClick={() => setBreakerMode(mode)}
                    className={`text-xs px-2 py-1.5 rounded transition-colors ${
                      breakerMode === mode
                        ? 'bg-orange-600 text-white'
                        : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                    }`}
                  >
                    {mode === 'prefix' && '⬅️ Prefix'}
                    {mode === 'suffix' && 'Suffix ➡️'}
                    {mode === 'both' && '↔️ Both'}
                    {mode === 'combo' && '🔗 Combo'}
                  </button>
                ))}
              </div>

              <div className="flex gap-2 mb-3">
                <button
                  onClick={selectAllBreakers}
                  className="text-xs px-2 py-1 bg-green-900/40 text-green-400 rounded hover:bg-green-900/60 transition-colors"
                >
                  Tout
                </button>
                <button
                  onClick={deselectAllBreakers}
                  className="text-xs px-2 py-1 bg-red-900/40 text-red-400 rounded hover:bg-red-900/60 transition-colors"
                >
                  Rien
                </button>
              </div>

              <div className="flex flex-wrap gap-1.5 mb-3">
                {allBreakers.map(breaker => {
                  const isSelected = selectedBreakers.includes(breaker.id);
                  const isCustom = breaker.id.startsWith('custom-');
                  return (
                    <div key={breaker.id} className="relative group">
                      <button
                        onClick={() => toggleBreaker(breaker.id)}
                        className={`px-2 py-1 rounded text-xs font-mono transition-all ${
                          isSelected
                            ? 'bg-orange-600/80 text-white border border-orange-500'
                            : 'bg-gray-800 text-gray-400 border border-gray-700 hover:border-gray-500'
                        } ${isCustom ? 'pr-5' : ''}`}
                        title={breaker.description}
                      >
                        {breaker.label}
                      </button>
                      {isCustom && (
                        <button
                          onClick={(e) => { e.stopPropagation(); removeCustomBreaker(breaker.id); }}
                          className="absolute -top-1 -right-1 w-3.5 h-3.5 bg-red-600 rounded-full text-white text-[8px] flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity"
                        >
                          ✕
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* Custom breaker input */}
              <div className="flex gap-2">
                <input
                  type="text"
                  value={customBreaker}
                  onChange={e => setCustomBreaker(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addCustomBreaker()}
                  placeholder="Custom breaker..."
                  className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-orange-400 focus:outline-none focus:border-orange-500"
                />
                <button
                  onClick={addCustomBreaker}
                  className="px-3 py-1.5 bg-orange-600 text-white rounded text-xs hover:bg-orange-700 transition-colors"
                >
                  + Add
                </button>
              </div>

              {selectedBreakers.length > 0 && (
                <div className="mt-3 p-2 bg-gray-900/80 rounded border border-gray-800">
                  <p className="text-xs text-gray-400 mb-1">Mode: <span className="text-orange-400 font-medium">{breakerMode}</span></p>
                  <p className="text-xs text-gray-400">
                    Sélectionné:{' '}
                    <span className="text-orange-300 font-mono">
                      {selectedBreakers
                        .map(id => allBreakers.find(b => b.id === id)?.label || id)
                        .join(' ')}
                    </span>
                  </p>
                  {breakerMode === 'combo' && (
                    <p className="text-xs text-gray-500 mt-1">
                      Préfixe combiné:{' '}
                      <span className="text-yellow-400 font-mono">
                        {selectedBreakers
                          .map(id => allBreakers.find(b => b.id === id)?.char || '')
                          .join('')}
                      </span>
                    </p>
                  )}
                </div>
              )}
            </Section>

            {/* Options */}
            <Section title="⚙️ Options">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={includeComments}
                  onChange={e => setIncludeComments(e.target.checked)}
                  className="accent-red-500"
                />
                <span className="text-gray-300">Inclure commentaires dans l'export</span>
              </label>
            </Section>
          </div>

          {/* Right column - Output */}
          <div className="lg:col-span-2 space-y-4">
            {/* Actions bar */}
            <div className="flex flex-wrap items-center gap-3">
              <button
                onClick={handleDownload}
                className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-red-600 to-orange-600 text-white rounded-lg font-medium text-sm hover:from-red-700 hover:to-orange-700 transition-all shadow-lg shadow-red-900/30"
              >
                <span>📥</span> Download Wordlist
              </button>
              <button
                onClick={handleCopy}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all ${
                  copied
                    ? 'bg-green-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700 border border-gray-700'
                }`}
              >
                <span>{copied ? '✅' : '📋'}</span> {copied ? 'Copié!' : 'Copier tout'}
              </button>
              <button
                onClick={() => setShowPreview(!showPreview)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg font-medium text-sm transition-all ${
                  showPreview
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-800 text-gray-300 hover:bg-gray-700 border border-gray-700'
                }`}
              >
                <span>👁️</span> {showPreview ? 'Masquer Raw' : 'Voir Raw'}
              </button>
            </div>

            {/* Usage hints */}
            <div className="bg-gray-900/60 border border-gray-800 rounded-lg p-4 space-y-2">
              <h3 className="text-sm font-semibold text-gray-300">📌 Usage rapide</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                <CodeBlock label="ffuf" code={`ffuf -u https://TARGET/PARAM -w blind_xss_wordlist.txt`} />
                <CodeBlock label="Callback server" code={`python3 -m http.server 80`} />
              </div>
            </div>

            {/* Search */}
            <div className="relative">
              <input
                type="text"
                value={searchFilter}
                onChange={e => setSearchFilter(e.target.value)}
                placeholder="🔍 Filtrer les payloads (ID, description, contenu...)"
                className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-300 focus:outline-none focus:border-red-500 focus:ring-1 focus:ring-red-500/30"
              />
              {searchFilter && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500">
                  {filteredPayloads.length} résultats
                </span>
              )}
            </div>

            {/* Raw preview */}
            {showPreview && (
              <div className="bg-gray-950 border border-gray-800 rounded-lg overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-900/50 border-b border-gray-800">
                  <span className="text-xs text-gray-500">blind_xss_wordlist.txt</span>
                  <span className="text-xs text-gray-600">{wordlistContent.split('\n').length} lines</span>
                </div>
                <pre className="p-4 text-xs font-mono text-green-400 overflow-auto max-h-96 whitespace-pre">
                  {wordlistContent.substring(0, 5000)}
                  {wordlistContent.length > 5000 && '\n\n... (tronqué pour la prévisualisation)'}
                </pre>
              </div>
            )}

            {/* Payload list by category */}
            <div className="space-y-3">
              {selectedCategories.map(cat => {
                const catPayloads = filteredPayloads.filter(p => p.category === cat);
                if (catPayloads.length === 0) return null;
                const info = CATEGORY_INFO[cat];
                const isExpanded = expandedCat === cat;

                return (
                  <div key={cat} className="bg-gray-900/40 border border-gray-800 rounded-lg overflow-hidden">
                    <button
                      onClick={() => setExpandedCat(isExpanded ? null : cat)}
                      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors"
                    >
                      <span className="text-xl">{info.icon}</span>
                      <div className="flex-1 text-left">
                        <span className="text-sm font-semibold text-gray-200">{info.label}</span>
                        <span className="text-xs text-gray-500 ml-2">{info.desc}</span>
                      </div>
                      <span className="text-xs px-2 py-0.5 bg-red-900/40 text-red-400 rounded">
                        {catPayloads.length}
                      </span>
                      <span className={`text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`}>
                        ▼
                      </span>
                    </button>

                    {isExpanded && (
                      <div className="border-t border-gray-800 max-h-[600px] overflow-auto">
                        {catPayloads.map((p, i) => (
                          <PayloadRow key={`${p.pid}-${i}`} payload={p} />
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Stats footer */}
            <div className="bg-gray-900/40 border border-gray-800 rounded-lg p-4">
              <h3 className="text-sm font-semibold text-gray-300 mb-3">📊 Distribution</h3>
              <div className="space-y-1.5">
                {selectedCategories.map(cat => {
                  const count = stats.catCounts[cat] || 0;
                  const maxCount = Math.max(...Object.values(stats.catCounts), 1);
                  const pct = (count / maxCount) * 100;
                  const info = CATEGORY_INFO[cat];
                  return (
                    <div key={cat} className="flex items-center gap-2 text-xs">
                      <span className="w-20 text-gray-500 font-medium">{info.label}</span>
                      <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-red-600 to-orange-500 rounded-full transition-all duration-500"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="w-8 text-right text-gray-400">{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-gray-800 mt-8 py-4 text-center text-xs text-gray-600">
        Blind XSS Payload Generator • {stats.total} payloads ready • For authorized testing only
      </footer>
    </div>
  );
}

// ── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-gray-900/60 border border-gray-800 rounded-lg px-4 py-3">
      <p className="text-xs text-gray-500">{label}</p>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  );
}

function Section({ title, defaultOpen = false, children }: { title: string; defaultOpen?: boolean; children: React.ReactNode }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-gray-900/40 border border-gray-800 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-gray-800/30 transition-colors"
      >
        <span className="text-sm font-semibold text-gray-200">{title}</span>
        <span className={`text-gray-500 transition-transform text-xs ${open ? 'rotate-180' : ''}`}>▼</span>
      </button>
      {open && <div className="px-4 pb-4 border-t border-gray-800 pt-3">{children}</div>}
    </div>
  );
}

function PayloadRow({ payload }: { payload: Payload }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(payload.payload).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };

  return (
    <div className="flex gap-2 px-4 py-2.5 border-b border-gray-800/50 hover:bg-gray-800/20 transition-colors group">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-[10px] font-mono px-1.5 py-0.5 bg-red-900/40 text-red-400 rounded shrink-0">
            {payload.pid}
          </span>
          <span className="text-xs text-gray-500 truncate">{payload.description}</span>
        </div>
        <pre className="text-xs font-mono text-green-400/80 whitespace-pre-wrap break-all leading-relaxed">
          {payload.payload}
        </pre>
      </div>
      <button
        onClick={handleCopy}
        className={`shrink-0 px-2 py-1 h-fit rounded text-xs opacity-0 group-hover:opacity-100 transition-all ${
          copied ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
        }`}
      >
        {copied ? '✓' : '📋'}
      </button>
    </div>
  );
}

function CodeBlock({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div
      className="bg-gray-950 rounded px-3 py-2 cursor-pointer hover:bg-gray-900 transition-colors group"
      onClick={() => {
        navigator.clipboard.writeText(code).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
    >
      <span className="text-[10px] text-gray-600 uppercase">{label}</span>
      <pre className="text-xs font-mono text-yellow-400/80 truncate">{code}</pre>
      <span className={`text-[10px] ${copied ? 'text-green-400' : 'text-gray-700 group-hover:text-gray-500'}`}>
        {copied ? '✓ copié' : 'click to copy'}
      </span>
    </div>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 12 12" className="w-3 h-3 text-white" fill="none" stroke="currentColor" strokeWidth={2}>
      <path d="M2 6l3 3 5-5" />
    </svg>
  );
}

export default App;
