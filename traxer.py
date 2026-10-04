#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║                        T R A X E R T O O L                        ║
║     Multitool de Ciberseguridad y Hacking Ético — Todo en 1       ║
║              Comunidad Traxer (YouTube)                           ║
╚══════════════════════════════════════════════════════════════════╝

Este archivo contiene TODA la herramienta en un solo .py — no necesita
carpetas extra ni imports locales (coremods, modules, etc). Solo
descárgalo y corre:

    python3 traxer.py

Compatible con Termux, Kali Linux, Debian/Ubuntu, Arch, WSL — cualquier
sistema con Python 3.8+.

Funciones opcionales (si no instalas estas librerías, el resto de la
tool funciona igual, solo se desactivan esas funciones puntuales):
    pip install Pillow        -> EXIF, limpieza de metadatos, esteganografía
    pip install phonenumbers  -> lookup de número telefónico

AVISO LEGAL:
Esta herramienta es solo para fines educativos y de seguridad ética.
Úsala únicamente sobre sistemas, redes o dominios de tu propiedad, o
con autorización explícita por escrito. El autor y la comunidad Traxer
no se hacen responsables del mal uso de esta herramienta.
"""

import sys
import os
import socket
import ssl
import shutil
import secrets
import string
import math
import re
import hashlib
import json
import base64
import datetime
import concurrent.futures
import urllib.request
import urllib.parse
import urllib.error

try:
    from PIL import Image
    PIL_DISPONIBLE = True
except ImportError:
    PIL_DISPONIBLE = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    PHONENUMBERS_DISPONIBLE = True
except ImportError:
    PHONENUMBERS_DISPONIBLE = False


# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: INTERFAZ (colores, banner, tablas)                      ║
# ╚══════════════════════════════════════════════════════════════════╝


import shutil

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(text, color):
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def ok(text):
    print(c(f"[+] {text}", "green"))


def warn(text):
    print(c(f"[!] {text}", "yellow"))


def error(text):
    print(c(f"[x] {text}", "red"))


def info(text):
    print(c(f"[*] {text}", "cyan"))


BANNER = r"""
 _______                          _____           _
|__   __|                        |_   _|         | |
   | |_ __ __ ___  _____ _ __      | |  ___   ___ | |
   | | '__/ _` \ \/ / _ \ '__|     | | / _ \ / _ \| |
   | | | | (_| |>  <  __/ |       _| || (_) | (_) | |
   |_|_|  \__,_/_/\_\___|_|      |_____\___/ \___/|_|
"""


def print_banner():
    width = shutil.get_terminal_size((80, 20)).columns
    print(c(BANNER, "cyan"))
    linea = "═" * min(width, 58)
    print(c(linea, "magenta"))
    print(c("      Multitool de Ciberseguridad y Hacking Ético", "bold"))
    print(c("           by Traxer  •  youtube.com", "dim"))
    print(c(linea, "magenta"))
    print(c("  Úsala solo en sistemas propios o con autorización.", "yellow"))
    print(c(linea, "magenta"))


def print_table(headers, rows):
    if not rows:
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    def fmt_row(row, color=None):
        cells = [str(cell).ljust(widths[i]) for i, cell in enumerate(row)]
        line = " │ ".join(cells)
        return c(line, color) if color else line

    print(fmt_row(headers, "bold"))
    print("─┼─".join("─" * w for w in widths))
    for row in rows:
        print(fmt_row(row))
    print()


def pause():
    input(c("\nPresiona ENTER para continuar...", "dim"))


def ask(prompt):
    return input(c(f"➜ {prompt}: ", "cyan")).strip()

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: RED Y RECONOCIMIENTO                                     ║
# ╚══════════════════════════════════════════════════════════════════╝

import socket
import ssl
import datetime
import concurrent.futures


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def scan_port(host, port, timeout=0.8):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            return port, result == 0
    except Exception:
        return port, False


def port_scanner(host, ports=None, timeout=0.8, max_workers=100):
    """Escaneo TCP connect simple. Úsalo solo en hosts propios o autorizados."""
    ip = resolve_host(host)
    if not ip:
        warn(f"No se pudo resolver el host: {host}")
        return []

    ports = ports or list(COMMON_PORTS.keys())
    info(f"Escaneando {host} ({ip}) — {len(ports)} puertos...")

    abiertos = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(scan_port, ip, p, timeout) for p in ports]
        for f in concurrent.futures.as_completed(futures):
            port, is_open = f.result()
            if is_open:
                servicio = COMMON_PORTS.get(port, "Desconocido")
                abiertos.append((port, servicio))

    abiertos.sort()
    if abiertos:
        print_table(["Puerto", "Servicio"], [[str(p), s] for p, s in abiertos])
    else:
        warn("No se encontraron puertos abiertos en la lista analizada.")
    return abiertos


def whois_lookup(domain):
    """WHOIS básico usando sockets contra servidores whois públicos (sin libs externas)."""
    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "dev": "whois.nic.google",
    }
    tld = domain.split(".")[-1].lower()
    server = servers.get(tld, "whois.iana.org")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((server, 43))
            s.send((domain + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode(errors="ignore")
    except Exception as e:
        warn(f"Error consultando WHOIS ({server}): {e}")
        return None


def dns_lookup(domain):
    """Resolución DNS básica (A record) + intento de reverse DNS."""
    resultados = {}
    try:
        resultados["A"] = socket.gethostbyname_ex(domain)
    except socket.gaierror as e:
        warn(f"No se pudo resolver {domain}: {e}")
        return resultados

    ip = resultados["A"][2][0]
    try:
        resultados["PTR"] = socket.gethostbyaddr(ip)
    except Exception:
        resultados["PTR"] = None

    return resultados


def check_tls_cert(host, port=443):
    """Revisa certificado TLS: emisor, validez y fecha de expiración."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except Exception as e:
        warn(f"No se pudo obtener el certificado: {e}")
        return None

    expira = cert.get("notAfter")
    if expira:
        fecha_exp = datetime.datetime.strptime(expira, "%b %d %H:%M:%S %Y %Z")
        dias_restantes = (fecha_exp - datetime.datetime.utcnow()).days
        if dias_restantes < 0:
            warn("¡El certificado ya expiró!")
        elif dias_restantes < 30:
            warn(f"El certificado expira pronto: {dias_restantes} días restantes.")
        else:
            ok(f"Certificado válido. Expira en {dias_restantes} días ({expira}).")
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print_table(["Campo", "Valor"], [
        ["Dominio", host],
        ["Emisor", issuer.get("organizationName", "N/A")],
        ["Válido hasta", expira or "N/A"],
    ])
    return cert


def check_security_headers(url):
    """Analiza headers de seguridad HTTP comunes usando solo librerías estándar."""
    from urllib.request import urlopen, Request
    from urllib.error import URLError

    if not url.startswith("http"):
        url = "https://" + url

    headers_a_revisar = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    req = Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        resp = urlopen(req, timeout=6)
        headers = dict(resp.headers)
    except URLError as e:
        warn(f"No se pudo conectar a {url}: {e}")
        return None

    filas = []
    for h in headers_a_revisar:
        presente = h in headers
        valor = headers.get(h, "— ausente —")
        filas.append([h, c("✓", "green") if presente else c("✗", "red"), valor[:50]])

    print_table(["Header", "¿Presente?", "Valor"], filas)
    return headers-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: CRIPTOGRAFÍA Y CONTRASEÑAS                               ║
# ╚══════════════════════════════════════════════════════════════════╝

import hashlib
import secrets
import string
import math
import re



def hash_text(text, algorithm="sha256"):
    algorithm = algorithm.lower()
    if algorithm not in hashlib.algorithms_available:
        warn(f"Algoritmo no soportado: {algorithm}")
        return None
    h = hashlib.new(algorithm)
    h.update(text.encode())
    return h.hexdigest()


def hash_all(text):
    algos = ["md5", "sha1", "sha256", "sha512"]
    filas = [[a.upper(), hash_text(text, a)] for a in algos]
    print_table(["Algoritmo", "Hash"], filas)


def hash_file(filepath, algorithm="sha256"):
    algorithm = algorithm.lower()
    if algorithm not in hashlib.algorithms_available:
        warn(f"Algoritmo no soportado: {algorithm}")
        return None
    h = hashlib.new(algorithm)
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
    except FileNotFoundError:
        warn(f"Archivo no encontrado: {filepath}")
        return None
    return h.hexdigest()


def verify_integrity(filepath, expected_hash, algorithm="sha256"):
    resultado = hash_file(filepath, algorithm)
    if resultado is None:
        return False
    coincide = resultado.lower() == expected_hash.lower().strip()
    if coincide:
        ok("✓ El hash coincide. El archivo es íntegro.")
    else:
        warn("✗ El hash NO coincide. El archivo pudo ser alterado.")
        info(f"Calculado: {resultado}")
        info(f"Esperado : {expected_hash}")
    return coincide


def password_entropy(password):
    """Calcula la entropía aproximada en bits según el conjunto de caracteres usado."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0:
        return 0
    return len(password) * math.log2(pool)


def check_password_strength(password):
    entropia = password_entropy(password)
    longitud = len(password)

    comunes = {
        "123456", "password", "12345678", "qwerty", "abc123",
        "111111", "123123", "admin", "letmein", "welcome",
        "iloveyou", "contraseña", "12345", "123456789",
    }

    problemas = []
    if longitud < 8:
        problemas.append("Muy corta (mínimo recomendado: 12 caracteres)")
    if password.lower() in comunes:
        problemas.append("¡Está en listas de contraseñas filtradas/comunes!")
    if not re.search(r"[A-Z]", password):
        problemas.append("Sin mayúsculas")
    if not re.search(r"[a-z]", password):
        problemas.append("Sin minúsculas")
    if not re.search(r"[0-9]", password):
        problemas.append("Sin números")
    if not re.search(r"[^a-zA-Z0-9]", password):
        problemas.append("Sin símbolos")

    if entropia < 28:
        nivel = c_level("Muy débil", "red")
    elif entropia < 36:
        nivel = c_level("Débil", "red")
    elif entropia < 60:
        nivel = c_level("Razonable", "yellow")
    elif entropia < 80:
        nivel = c_level("Fuerte", "green")
    else:
        nivel = c_level("Muy fuerte", "green")

    print_table(["Métrica", "Valor"], [
        ["Longitud", str(longitud)],
        ["Entropía estimada", f"{entropia:.1f} bits"],
        ["Nivel", nivel],
    ])

    if problemas:
        warn("Puntos a mejorar:")
        for p in problemas:
            print(f"  - {p}")
    else:
        ok("No se detectaron debilidades evidentes.")

    return entropia


def c_level(text, color):
    return c(text, color)


def generate_password(length=16, use_symbols=True):
    alphabet = string.ascii_letters + string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{}"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_passphrase(num_words=5):
    """Genera una passphrase tipo diceware con una mini wordlist embebida.
    Para uso real se recomienda una wordlist EFF completa."""
    wordlist = [
        "atomo", "bosque", "cactus", "delfin", "eco", "fuego", "galaxia",
        "huracan", "iman", "jaguar", "kilo", "luna", "montana", "nube",
        "oceano", "planeta", "quasar", "rio", "sol", "tigre", "universo",
        "volcan", "web", "xenon", "yunque", "zafiro", "aurora", "brisa",
        "cometa", "dragon",
    ]
    return "-".join(secrets.choice(wordlist) for _ in range(num_words))


def base64_tools(text, mode="encode"):
    import base64
    try:
        if mode == "encode":
            return base64.b64encode(text.encode()).decode()
        else:
            return base64.b64decode(text.encode()).decode()
    except Exception as e:
        warn(f"Error procesando Base64: {e}")
        return None-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: OSINT (reconocimiento pasivo)                            ║
# ╚══════════════════════════════════════════════════════════════════╝

import json
import urllib.request
import urllib.parse



def _http_get_json(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        return json.loads(data)
    except Exception as e:
        warn(f"Error en la petición: {e}")
        return None


def subdomain_enum(domain):
    """Enumeración PASIVA de subdominios usando certificados públicos (crt.sh)."""
    info(f"Buscando subdominios de {domain} en Certificate Transparency logs...")
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    data = _http_get_json(url)
    if not data:
        warn("No se obtuvieron resultados (crt.sh puede estar caído o saturado).")
        return []

    subs = set()
    for entry in data:
        nombre = entry.get("name_value", "")
        for linea in nombre.split("\n"):
            linea = linea.strip().lower()
            if linea and "*" not in linea:
                subs.add(linea)

    subs = sorted(subs)
    if subs:
        ok(f"Se encontraron {len(subs)} subdominios únicos.")
        for s in subs:
            print(f"  - {s}")
    else:
        warn("No se encontraron subdominios.")
    return subs


def ip_geolocation(ip_or_host):
    """Geolocalización aproximada de una IP/host vía ip-api.com (uso gratuito, sin API key)."""
    url = f"http://ip-api.com/json/{urllib.parse.quote(ip_or_host)}?lang=es"
    data = _http_get_json(url)
    if not data or data.get("status") != "success":
        warn(f"No se pudo geolocalizar: {data.get('message') if data else 'sin respuesta'}")
        return None

    print_table(["Campo", "Valor"], [
        ["IP", data.get("query", "N/A")],
        ["País", data.get("country", "N/A")],
        ["Región", data.get("regionName", "N/A")],
        ["Ciudad", data.get("city", "N/A")],
        ["ISP", data.get("isp", "N/A")],
        ["Organización", data.get("org", "N/A")],
        ["Zona horaria", data.get("timezone", "N/A")],
        ["Lat/Lon", f"{data.get('lat')}, {data.get('lon')}"],
    ])
    return data


def email_breach_hint(email):
    """
    No realiza consultas a APIs de terceros que requieran clave.
    Da orientación al usuario sobre cómo verificar si su correo fue
    comprometido en filtraciones conocidas, de forma responsable.
    """
    info("TraxerTool no almacena ni consulta tu correo en bases externas automáticamente.")
    print("Para revisar si tu correo apareció en alguna filtración conocida, visita:")
    print("  - https://haveibeenpwned.com")
    print("  - https://monitor.firefox.com")
    print("Nunca pegues contraseñas reales en formularios de terceros no verificados.")-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: DETECCIÓN DE VULNERABILIDADES (pasiva)                   ║
# ╚══════════════════════════════════════════════════════════════════╝

import socket
import json
import urllib.request
import urllib.parse
import urllib.error


# Rutas comunes que, si quedan expuestas sin autenticación, suelen indicar
# una mala configuración (no es un ataque, solo se pide la URL como
# cualquier navegador lo haría).
RUTAS_SENSIBLES = [
    "/.git/config",
    "/.env",
    "/.env.local",
    "/wp-config.php.bak",
    "/backup.zip",
    "/backup.sql",
    "/phpinfo.php",
    "/.DS_Store",
    "/server-status",
    "/.htpasswd",
    "/admin/",
    "/.well-known/security.txt",
]


def banner_grab(host, port, timeout=4):
    """Se conecta a un puerto TCP y lee lo primero que el servicio anuncia
    (banner). Muchos servicios (FTP, SSH, SMTP, HTTP) revelan su versión
    exacta aquí, lo cual es la primera pista para saber si hay un CVE
    conocido para esa versión."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if port in (80, 8080, 443, 8443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner
    except Exception as e:
        warn(f"No se pudo obtener banner de {host}:{port} ({e})")
        return None


def banner_scan(host, ports):
    """Hace banner grabbing sobre una lista de puertos y muestra resultados."""
    filas = []
    for port in ports:
        banner = banner_grab(host, port)
        if banner:
            primera_linea = banner.split("\n")[0][:70]
            filas.append([str(port), primera_linea])
    if filas:
        print_table(["Puerto", "Banner (primera línea)"], filas)
    else:
        warn("No se obtuvieron banners en los puertos indicados.")
    return filas


def buscar_cves(keyword, resultados_max=8):
    """Busca CVEs públicos relacionados a un software/versión usando la
    API oficial del NVD (National Vulnerability Database, de NIST).
    Ejemplo de keyword: 'Apache 2.4.49' o 'OpenSSH 7.2'.
    """
    info(f"Buscando CVEs públicos para: {keyword} ...")
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={resultados_max}"
    )
    req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        warn(f"El NVD respondió con error {e.code}. Intenta de nuevo en unos segundos "
             f"(la API pública tiene límite de peticiones).")
        return []
    except Exception as e:
        warn(f"No se pudo consultar el NVD: {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        warn("No se encontraron CVEs para esa búsqueda.")
        return []

    filas = []
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descripciones = cve.get("descriptions", [])
        desc_es_en = next((d["value"] for d in descripciones if d.get("lang") == "en"), "")
        severidad = "N/A"
        metrics = cve.get("metrics", {})
        for clave in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if clave in metrics and metrics[clave]:
                severidad = str(metrics[clave][0]["cvssData"].get("baseScore", "N/A"))
                break
        filas.append([cve_id, severidad, desc_es_en[:80] + ("..." if len(desc_es_en) > 80 else "")])

    print_table(["CVE", "Score CVSS", "Descripción"], filas)
    ok(f"Se encontraron {len(vulns)} resultado(s). Consulta cada CVE en https://nvd.nist.gov/vuln/detail/<CVE-ID>")
    return filas


def check_exposed_paths(base_url, rutas=None, timeout=5):
    """Revisa si rutas/archivos sensibles comunes están expuestos
    públicamente (solo hace peticiones GET normales, como un navegador)."""
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    base_url = base_url.rstrip("/")
    rutas = rutas or RUTAS_SENSIBLES

    info(f"Revisando {len(rutas)} rutas sensibles comunes en {base_url} ...")
    encontrados = []
    for ruta in rutas:
        url = base_url + ruta
        req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"}, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                codigo = resp.status
        except urllib.error.HTTPError as e:
            codigo = e.code
        except Exception:
            continue

        if codigo == 200:
            encontrados.append((ruta, codigo))

    if encontrados:
        warn(f"¡Atención! {len(encontrados)} ruta(s) sensible(s) accesible(s):")
        print_table(["Ruta", "Código HTTP"], [[r, str(cod)] for r, cod in encontrados])
        warn("Si este es tu sitio, revisa la configuración del servidor para bloquear el acceso.")
    else:
        ok("No se encontraron rutas sensibles expuestas de la lista revisada.")
    return encontrados


def full_vuln_report(host):
    """Reporte combinado: banners de puertos web comunes + rutas sensibles."""
    print(c(f"\n=== Reporte de vulnerabilidades pasivo: {host} ===", "bold"))
    banner_scan(host, [80, 443, 21, 22, 25])
    check_exposed_paths(host)-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: FORENSE Y PRIVACIDAD DE ARCHIVOS                         ║
# ╚══════════════════════════════════════════════════════════════════╝

import os
import secrets


try:
    from PIL import Image
    PIL_DISPONIBLE = True
except ImportError:
    PIL_DISPONIBLE = False


def _requiere_pillow():
    warn("Esta función necesita la librería Pillow.")
    info("Instálala con: pip install Pillow")


def exif_viewer(ruta_imagen):
    """Muestra los metadatos EXIF de una imagen (útil para saber si una
    foto revela ubicación GPS, modelo de cámara, fecha, etc. — muy usado
    en OSINT y en concientización de privacidad)."""
    if not PIL_DISPONIBLE:
        _requiere_pillow()
        return None

    if not os.path.isfile(ruta_imagen):
        warn(f"No se encontró el archivo: {ruta_imagen}")
        return None

    try:
        img = Image.open(ruta_imagen)
        exif_data = img.getexif()
    except Exception as e:
        warn(f"No se pudo leer la imagen: {e}")
        return None

    if not exif_data:
        warn("Esta imagen no tiene metadatos EXIF (o fueron eliminados).")
        return None

    from PIL.ExifTags import TAGS
    filas = []
    for tag_id, valor in exif_data.items():
        tag = TAGS.get(tag_id, tag_id)
        filas.append([str(tag), str(valor)[:60]])

    print_table(["Campo EXIF", "Valor"], filas)
    ok(f"Se encontraron {len(filas)} campos de metadatos.")
    warn("Si vas a compartir esta imagen públicamente, considera limpiar sus metadatos.")
    return filas


def strip_exif(ruta_imagen, ruta_salida=None):
    """Elimina todos los metadatos EXIF de una imagen y guarda una copia limpia."""
    if not PIL_DISPONIBLE:
        _requiere_pillow()
        return None

    if not os.path.isfile(ruta_imagen):
        warn(f"No se encontró el archivo: {ruta_imagen}")
        return None

    ruta_salida = ruta_salida or (ruta_imagen.rsplit(".", 1)[0] + "_limpio." + ruta_imagen.rsplit(".", 1)[-1])
    try:
        img = Image.open(ruta_imagen)
        datos = list(img.getdata())
        img_limpia = Image.new(img.mode, img.size)
        img_limpia.putdata(datos)
        img_limpia.save(ruta_salida)
    except Exception as e:
        warn(f"No se pudo limpiar la imagen: {e}")
        return None

    ok(f"Imagen sin metadatos guardada en: {ruta_salida}")
    return ruta_salida


def _texto_a_bits(texto):
    bits = "".join(format(byte, "08b") for byte in texto.encode("utf-8"))
    bits += "00000000" * 2  # delimitador de fin de mensaje (doble null byte)
    return bits


def _bits_a_texto(bits):
    bytes_list = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    datos = bytearray()
    ceros_seguidos = 0
    for b in bytes_list:
        valor = int(b, 2)
        if valor == 0:
            ceros_seguidos += 1
            if ceros_seguidos >= 2:
                break
        else:
            ceros_seguidos = 0
        datos.append(valor)
    try:
        return datos.decode("utf-8", errors="ignore").rstrip("\x00")
    except Exception:
        return ""


def stego_hide(ruta_imagen, texto, ruta_salida=None):
    """Oculta un mensaje de texto dentro de una imagen PNG usando LSB
    (bit menos significativo de cada canal de color). La imagen se ve
    idéntica a simple vista, pero contiene el mensaje embebido."""
    if not PIL_DISPONIBLE:
        _requiere_pillow()
        return None
    if not os.path.isfile(ruta_imagen):
        warn(f"No se encontró el archivo: {ruta_imagen}")
        return None

    img = Image.open(ruta_imagen).convert("RGB")
    bits = _texto_a_bits(texto)
    capacidad = img.width * img.height * 3
    if len(bits) > capacidad:
        warn("El mensaje es demasiado largo para esta imagen.")
        return None

    pixeles = list(img.getdata())
    nuevos_pixeles = []
    idx = 0
    for r, g, b in pixeles:
        canal = [r, g, b]
        for i in range(3):
            if idx < len(bits):
                canal[i] = (canal[i] & ~1) | int(bits[idx])
                idx += 1
        nuevos_pixeles.append(tuple(canal))

    img_oculta = Image.new("RGB", img.size)
    img_oculta.putdata(nuevos_pixeles)
    ruta_salida = ruta_salida or (ruta_imagen.rsplit(".", 1)[0] + "_stego.png")
    img_oculta.save(ruta_salida, "PNG")
    ok(f"Mensaje ocultado. Imagen guardada en: {ruta_salida}")
    return ruta_salida


def stego_extract(ruta_imagen):
    """Extrae un mensaje oculto previamente con stego_hide()."""
    if not PIL_DISPONIBLE:
        _requiere_pillow()
        return None
    if not os.path.isfile(ruta_imagen):
        warn(f"No se encontró el archivo: {ruta_imagen}")
        return None

    img = Image.open(ruta_imagen).convert("RGB")
    bits = ""
    for r, g, b in img.getdata():
        for canal in (r, g, b):
            bits += str(canal & 1)

    mensaje = _bits_a_texto(bits)
    if mensaje:
        ok("Mensaje extraído:")
        print(c(mensaje, "green"))
    else:
        warn("No se encontró ningún mensaje oculto (o la imagen no tiene uno embebido con TraxerTool).")
    return mensaje


def secure_delete(ruta, pasadas=3):
    """Sobreescribe un archivo con datos aleatorios varias veces antes de
    eliminarlo, para dificultar su recuperación forense. No es infalible
    en SSDs modernos (por el wear-leveling), pero es mucho mejor que un
    borrado normal."""
    if not os.path.isfile(ruta):
        warn(f"No se encontró el archivo: {ruta}")
        return False

    tam = os.path.getsize(ruta)
    try:
        with open(ruta, "r+b") as f:
            for _ in range(pasadas):
                f.seek(0)
                f.write(secrets.token_bytes(tam))
                f.flush()
                os.fsync(f.fileno())
        os.remove(ruta)
    except Exception as e:
        warn(f"Error durante el borrado seguro: {e}")
        return False

    ok(f"Archivo sobreescrito {pasadas} veces y eliminado: {ruta}")
    return True-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: HERRAMIENTAS WEB AVANZADAS                               ║
# ╚══════════════════════════════════════════════════════════════════╝

import base64
import json
import re
import urllib.request
import urllib.error


METODOS_RIESGOSOS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def jwt_decode(token):
    """Decodifica un JWT (header + payload) SIN verificar la firma.
    Útil para inspeccionar tokens propios o de pruebas y entender qué
    datos llevan. No valida autenticidad."""
    partes = token.strip().split(".")
    if len(partes) != 3:
        warn("Eso no parece un JWT válido (debe tener 3 partes separadas por '.').")
        return None

    def _decode_part(p):
        p += "=" * (-len(p) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(p))
        except Exception:
            return None

    header = _decode_part(partes[0])
    payload = _decode_part(partes[1])

    if header:
        info("Header:")
        print(json.dumps(header, indent=2, ensure_ascii=False))
    if payload:
        info("Payload:")
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    warn("Recuerda: esto NO verifica la firma. Un JWT puede decodificarse "
         "siempre, pero eso no significa que sea válido ni auténtico.")
    return {"header": header, "payload": payload}


def analyze_email_headers(raw_headers):
    """Analiza cabeceras crudas de un correo (pegadas tal cual) buscando
    señales típicas de phishing/spoofing: SPF/DKIM/DMARC fallidos,
    discrepancias entre 'From' y 'Return-Path', cadena de 'Received'."""
    resultado = {}

    spf = re.search(r"spf=(\w+)", raw_headers, re.IGNORECASE)
    dkim = re.search(r"dkim=(\w+)", raw_headers, re.IGNORECASE)
    dmarc = re.search(r"dmarc=(\w+)", raw_headers, re.IGNORECASE)
    from_match = re.search(r"^From:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE)
    return_path = re.search(r"^Return-Path:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE)
    received = re.findall(r"^Received:\s*(.+)$", raw_headers, re.IGNORECASE | re.MULTILINE)

    filas = []
    for nombre, match in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
        valor = match.group(1).lower() if match else "no encontrado"
        filas.append([nombre, valor])
    print_table(["Autenticación", "Resultado"], filas)

    alertas = []
    for nombre, match in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
        if match and match.group(1).lower() not in ("pass",):
            alertas.append(f"{nombre} no pasó ({match.group(1)}) — señal de posible spoofing.")

    if from_match and return_path:
        from_email = re.search(r"[\w\.-]+@[\w\.-]+", from_match.group(1))
        return_email = re.search(r"[\w\.-]+@[\w\.-]+", return_path.group(1))
        if from_email and return_email and from_email.group().lower() != return_email.group().lower():
            alertas.append(
                f"El 'From' ({from_email.group()}) no coincide con el 'Return-Path' "
                f"({return_email.group()}) — común en spoofing."
            )

    if alertas:
        warn("Posibles señales de phishing/spoofing:")
        for a in alertas:
            print(f"  - {a}")
    else:
        ok("No se detectaron señales evidentes de spoofing en lo analizado.")

    if received:
        info(f"Cadena de servidores 'Received' ({len(received)} saltos, del más reciente al origen):")
        for i, r in enumerate(received[:6]):
            print(f"  {i+1}. {r[:90]}")

    resultado = {"spf": spf, "dkim": dkim, "dmarc": dmarc, "alertas": alertas}
    return resultado


def robots_txt_check(domain):
    """Descarga y muestra el robots.txt de un dominio — a veces revela
    rutas 'ocultas' que el propio sitio no quiere que se indexen."""
    if not domain.startswith("http"):
        domain = "https://" + domain
    url = domain.rstrip("/") + "/robots.txt"

    req = urllib.request.Request(url, headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            contenido = resp.read().decode(errors="ignore")
    except Exception as e:
        warn(f"No se pudo obtener robots.txt: {e}")
        return None

    disallow = re.findall(r"^Disallow:\s*(.+)$", contenido, re.IGNORECASE | re.MULTILINE)
    if disallow:
        ok(f"Se encontraron {len(disallow)} rutas marcadas como 'Disallow':")
        for d in disallow:
            print(f"  - {d.strip()}")
    else:
        info("No hay reglas 'Disallow' o el archivo está vacío.")
    return disallow


def check_http_methods(url):
    """Envía una petición OPTIONS para ver qué métodos HTTP acepta el
    servidor. Métodos como PUT/DELETE/TRACE habilitados públicamente
    suelen ser una mala configuración."""
    if not url.startswith("http"):
        url = "https://" + url

    req = urllib.request.Request(url, method="OPTIONS", headers={"User-Agent": "TraxerTool/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            allow = resp.headers.get("Allow", "")
    except urllib.error.HTTPError as e:
        allow = e.headers.get("Allow", "") if e.headers else ""
    except Exception as e:
        warn(f"No se pudo consultar métodos HTTP: {e}")
        return None

    if not allow:
        warn("El servidor no devolvió un header 'Allow'. Puede que OPTIONS esté bloqueado.")
        return None

    metodos = [m.strip().upper() for m in allow.split(",")]
    riesgosos = [m for m in metodos if m in METODOS_RIESGOSOS]

    print_table(["Método", "¿Riesgoso?"], [
        [m, c("⚠ sí", "yellow") if m in riesgosos else "no"] for m in metodos
    ])
    if riesgosos:
        warn(f"Métodos potencialmente riesgosos habilitados: {', '.join(riesgosos)}")
    else:
        ok("No se detectaron métodos HTTP riesgosos habilitados públicamente.")
    return metodos


def typosquat_generator(domain):
    """Genera variantes típicas de 'typosquatting' de tu propio dominio
    (omisión, duplicación, intercambio de letras, vecinos de teclado).
    Úsalo para monitorear si alguien registró dominios parecidos al tuyo
    para hacer phishing a tu comunidad."""
    if "." not in domain:
        warn("Formato esperado: ejemplo.com")
        return []

    nombre, resto = domain.split(".", 1)
    variantes = set()

    # Omisión de una letra
    for i in range(len(nombre)):
        variantes.add(nombre[:i] + nombre[i + 1:])

    # Duplicación de una letra
    for i in range(len(nombre)):
        variantes.add(nombre[:i] + nombre[i] + nombre[i:])

    # Intercambio de letras adyacentes
    for i in range(len(nombre) - 1):
        lista = list(nombre)
        lista[i], lista[i + 1] = lista[i + 1], lista[i]
        variantes.add("".join(lista))

    # Sustitución por vecinos de teclado QWERTY (simplificado)
    vecinos = {
        "a": "sq", "b": "vn", "c": "xv", "d": "sf", "e": "wr", "f": "dg",
        "g": "fh", "h": "gj", "i": "uo", "j": "hk", "k": "jl", "l": "k",
        "m": "n", "n": "bm", "o": "ip", "p": "o", "q": "wa", "r": "et",
        "s": "ad", "t": "ry", "u": "yi", "v": "cb", "w": "qe", "x": "zc",
        "y": "tu", "z": "x",
    }
    for i, letra in enumerate(nombre):
        for v in vecinos.get(letra, ""):
            variantes.add(nombre[:i] + v + nombre[i + 1:])

    variantes.discard(nombre)
    dominios = sorted(f"{v}.{resto}" for v in variantes if v)

    ok(f"Se generaron {len(dominios)} variantes de '{domain}' para monitorear.")
    info("Puedes revisar cuáles están registradas con la opción de WHOIS del menú de Red.")
    for d in dominios[:40]:
        print(f"  - {d}")
    if len(dominios) > 40:
        print(f"  ... y {len(dominios) - 40} más.")
    return dominios


def my_public_ip():
    """Consulta tu IP pública actual usando un servicio simple de texto plano."""
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "TraxerTool/1.0"})
        with urllib.request.urlopen(req, timeout=6) as resp:
            ip = resp.read().decode().strip()
        ok(f"Tu IP pública actual es: {ip}")
        return ip
    except Exception as e:
        warn(f"No se pudo obtener la IP pública: {e}")
        return None


def url_expander(url, max_saltos=10):
    """Sigue redirecciones de una URL acortada SIN descargar el contenido
    final, solo para ver a dónde lleva realmente antes de hacer clic."""
    actual = url
    cadena = [actual]
    for _ in range(max_saltos):
        req = urllib.request.Request(actual, method="HEAD", headers={"User-Agent": "TraxerTool/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                final = resp.geturl()
            if final == actual:
                break
            cadena.append(final)
            actual = final
        except urllib.error.HTTPError as e:
            if e.headers and "Location" in e.headers:
                actual = e.headers["Location"]
                cadena.append(actual)
            else:
                break
        except Exception as e:
            warn(f"Error siguiendo la redirección: {e}")
            break

    info("Cadena de redirecciones:")
    for i, u in enumerate(cadena):
        print(f"  {i+1}. {u}")
    ok(f"Destino final: {cadena[-1]}")
    return cadena-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: OSINT-OPSEC (dorking, username, teléfono, IP)            ║
# ╚══════════════════════════════════════════════════════════════════╝

import urllib.request
import urllib.parse
import urllib.error
import datetime


try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pn_timezone
    PHONENUMBERS_DISPONIBLE = True
except ImportError:
    PHONENUMBERS_DISPONIBLE = False


# ──────────────────────────────────────────────────────────────
# 1) GOOGLE DORKING
# ──────────────────────────────────────────────────────────────

DORK_TEMPLATES = [
    'site:{t} filetype:pdf',
    'site:{t} filetype:xls OR filetype:xlsx',
    'site:{t} filetype:doc OR filetype:docx',
    'site:{t} ext:sql',
    'site:{t} ext:env',
    'site:{t} ext:log',
    'site:{t} intitle:"index of"',
    'site:{t} inurl:admin',
    'site:{t} inurl:login',
    'site:{t} inurl:config',
    'site:{t} "password" filetype:txt',
    'site:pastebin.com "{t}"',
    'site:github.com "{t}"',
    'site:linkedin.com/in "{t}"',
    'intext:"{t}" "confidential"',
]


def google_dorking(target):
    """Genera queries de Google Dorking para el objetivo (dominio, nombre
    de empresa, etc.) y manda los links de búsqueda directo a la terminal
    para que los abras manualmente en el navegador."""
    info(f"Generando dorks para: {target}")
    print()
    for plantilla in DORK_TEMPLATES:
        query = plantilla.format(t=target)
        url = "https://www.google.com/search?q=" + urllib.parse.quote(query)
        print(c(f"  [{query}]", "cyan"))
        print(f"  {url}\n")
    ok(f"Se generaron {len(DORK_TEMPLATES)} dorks. Ábrelos manualmente en tu navegador.")
    warn("Recuerda: solo investiga dominios/empresas propias o con autorización.")
    return DORK_TEMPLATES


# ──────────────────────────────────────────────────────────────
# 2) BÚSQUEDA DE USERNAME EN PLATAFORMAS
# ──────────────────────────────────────────────────────────────

PLATAFORMAS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Twitter/X": "https://x.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Reddit": "https://www.reddit.com/user/{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "Telegram": "https://t.me/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Facebook": "https://www.facebook.com/{u}",
}


def _check_url(url, timeout=6):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (TraxerTool)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def username_search(username):
    """Revisa si un username existe en varias plataformas (estilo Sherlock
    simplificado). Nota: algunas plataformas siempre devuelven 200 aunque
    el perfil no exista (anti-scraping), así que verifica manualmente los
    resultados marcados como 'posible'."""
    info(f"Buscando el username '{username}' en {len(PLATAFORMAS)} plataformas...")
    encontrados = []
    filas = []
    for nombre, plantilla in PLATAFORMAS.items():
        url = plantilla.format(u=username)
        codigo = _check_url(url)
        if codigo == 200:
            estado = c("✓ posible match", "green")
            encontrados.append((nombre, url))
        elif codigo in (404, 410):
            estado = c("no encontrado", "dim")
        elif codigo is None:
            estado = c("error de conexión", "red")
        else:
            estado = c(f"código {codigo}", "yellow")
        filas.append([nombre, estado, url])

    print_table(["Plataforma", "Resultado", "URL"], filas)
    if encontrados:
        ok(f"{len(encontrados)} posible(s) coincidencia(s) encontrada(s). Verifica manualmente cada perfil.")
    else:
        warn("No se encontraron coincidencias claras.")
    return encontrados


# ──────────────────────────────────────────────────────────────
# 3) LOOKUP DE NÚMERO TELEFÓNICO
# ──────────────────────────────────────────────────────────────

def phone_lookup(numero):
    """Analiza un número telefónico (formato internacional, ej. +521234567890):
    país, región aproximada, operador/compañía y zona(s) horaria(s).
    Usa la librería 'phonenumbers' (puerto de libphonenumber de Google),
    totalmente offline, sin consultar APIs externas."""
    if not PHONENUMBERS_DISPONIBLE:
        warn("Esta función necesita la librería 'phonenumbers'.")
        info("Instálala con: pip install phonenumbers")
        return None

    try:
        num = phonenumbers.parse(numero, None)
    except phonenumbers.NumberParseException as e:
        warn(f"Número inválido: {e}")
        info("Usa formato internacional, ej: +525512345678")
        return None

    if not phonenumbers.is_valid_number(num):
        warn("El número no parece válido según su formato internacional.")

    pais = geocoder.description_for_number(num, "es") or "Desconocido"
    operador = carrier.name_for_number(num, "es") or "No disponible (puede ser número portado o VOIP)"
    zonas = pn_timezone.time_zones_for_number(num)
    tipo = phonenumbers.number_type(num)

    tipos_legibles = {
        0: "Fijo", 1: "Móvil", 2: "Fijo o Móvil", 3: "Gratuito (800)",
        4: "Tarifa premium", 5: "Compartido", 6: "VOIP", 7: "Personal",
        8: "Buscapersonas", 9: "UAN", 10: "Voicemail", 27: "Desconocido",
    }

    filas = [
        ["Número formateado", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)],
        ["País/Región", pais],
        ["Código de país", f"+{num.country_code}"],
        ["Operador/Compañía", operador],
        ["Tipo de línea", tipos_legibles.get(tipo, "Desconocido")],
        ["Zona(s) horaria(s)", ", ".join(zonas) if zonas else "No disponible"],
        ["¿Número válido?", "Sí" if phonenumbers.is_valid_number(num) else "No"],
    ]

    if zonas:
        try:
            ahora_utc = datetime.datetime.utcnow()
            info(f"Hora UTC actual: {ahora_utc.strftime('%Y-%m-%d %H:%M')} (referencia para calcular la hora local)")
        except Exception:
            pass

    print_table(["Campo", "Valor"], filas)
    return filas


# ──────────────────────────────────────────────────────────────
# 4) GEOLOCALIZACIÓN + PUERTOS DE UNA IP
# ──────────────────────────────────────────────────────────────

def ip_geo_and_ports(ip, puertos=None):
    """Reporte combinado: geolocaliza la IP y además escanea sus puertos
    comunes, todo en un solo comando."""
    print(c(f"\n=== Reporte OSINT-OPSEC para {ip} ===", "bold"))
    info("Geolocalización:")
    ip_geolocation(ip)
    print()
    info("Escaneo de puertos:")
    port_scanner(ip, puertos)-e 

# ╔══════════════════════════════════════════════════════════════════╗
# ║  SECCIÓN: MENÚ PRINCIPAL                                           ║
# ╚══════════════════════════════════════════════════════════════════╝

def menu_red():
    while True:
        print(c("\n── RED Y RECONOCIMIENTO ──", "bold"))
        print(" 1) Escáner de puertos (TCP connect)")
        print(" 2) Consulta WHOIS")
        print(" 3) Resolución DNS / Reverse DNS")
        print(" 4) Revisar certificado TLS/SSL")
        print(" 5) Analizar headers de seguridad HTTP")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            host = ask("Host o IP objetivo")
            puertos_raw = ask("Puertos (ENTER = top comunes, ej '22,80,443' o '1-1000')")
            ports = None
            if puertos_raw:
                ports = parse_ports(puertos_raw)
            network.port_scanner(host, ports)
        elif op == "2":
            dominio = ask("Dominio (ej. ejemplo.com)")
            resultado = network.whois_lookup(dominio)
            if resultado:
                print(resultado)
        elif op == "3":
            dominio = ask("Dominio a resolver")
            res = network.dns_lookup(dominio)
            if res.get("A"):
                nombre, alias, ips = res["A"]
                print(c(f"\nHost: {nombre}", "green"))
                print(f"IPs: {', '.join(ips)}")
            if res.get("PTR"):
                print(f"PTR (reverse): {res['PTR'][0]}")
        elif op == "4":
            host = ask("Host (sin https://)")
            network.check_tls_cert(host)
        elif op == "5":
            url = ask("URL a analizar")
            network.check_security_headers(url)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def parse_ports(raw):
    ports = set()
    for parte in raw.split(","):
        parte = parte.strip()
        if "-" in parte:
            try:
                a, b = parte.split("-")
                ports.update(range(int(a), int(b) + 1))
            except ValueError:
                continue
        elif parte.isdigit():
            ports.add(int(parte))
    return sorted(ports) if ports else None


def menu_cripto():
    while True:
        print(c("\n── CRIPTOGRAFÍA Y CONTRASEÑAS ──", "bold"))
        print(" 1) Generar hash de un texto (MD5/SHA1/SHA256/SHA512)")
        print(" 2) Calcular hash de un archivo")
        print(" 3) Verificar integridad de un archivo contra un hash")
        print(" 4) Analizar fortaleza de una contraseña")
        print(" 5) Generar contraseña segura")
        print(" 6) Generar passphrase (estilo diceware)")
        print(" 7) Codificar / Decodificar Base64")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            texto = ask("Texto a hashear")
            crypto_tools.hash_all(texto)
        elif op == "2":
            ruta = ask("Ruta del archivo")
            algo = ask("Algoritmo (sha256/md5/sha1/sha512) [sha256]") or "sha256"
            h = crypto_tools.hash_file(ruta, algo)
            if h:
                ok(f"{algo.upper()}: {h}")
        elif op == "3":
            ruta = ask("Ruta del archivo")
            hash_esperado = ask("Hash esperado")
            algo = ask("Algoritmo [sha256]") or "sha256"
            crypto_tools.verify_integrity(ruta, hash_esperado, algo)
        elif op == "4":
            pwd = ask("Contraseña a analizar (no se guarda ni se envía a ningún lado)")
            crypto_tools.check_password_strength(pwd)
        elif op == "5":
            try:
                longitud = int(ask("Longitud [16]") or "16")
            except ValueError:
                longitud = 16
            simbolos = ask("¿Incluir símbolos? (s/n) [s]") or "s"
            pwd = crypto_tools.generate_password(longitud, simbolos.lower() != "n")
            ok(f"Contraseña generada: {pwd}")
        elif op == "6":
            try:
                n = int(ask("Número de palabras [5]") or "5")
            except ValueError:
                n = 5
            ok(f"Passphrase: {crypto_tools.generate_passphrase(n)}")
        elif op == "7":
            modo = ask("¿Codificar o decodificar? (c/d)")
            texto = ask("Texto")
            resultado = crypto_tools.base64_tools(
                texto, "encode" if modo.lower().startswith("c") else "decode"
            )
            if resultado is not None:
                ok(f"Resultado: {resultado}")
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_vulnerabilidades():
    while True:
        print(c("\n── DETECCIÓN DE VULNERABILIDADES (PASIVA) ──", "bold"))
        print(" 1) Banner grabbing (identificar versión de un servicio)")
        print(" 2) Buscar CVEs conocidos por software/versión")
        print(" 3) Revisar archivos/rutas sensibles expuestas")
        print(" 4) Reporte completo (banners + rutas sensibles)")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            host = ask("Host o IP")
            puertos_raw = ask("Puertos separados por coma [80,443,21,22,25]") or "80,443,21,22,25"
            ports = parse_ports(puertos_raw) or [80, 443, 21, 22, 25]
            vuln_scan.banner_scan(host, ports)
        elif op == "2":
            kw = ask("Software y versión (ej. 'OpenSSH 7.2' o 'Apache 2.4.49')")
            vuln_scan.buscar_cves(kw)
        elif op == "3":
            url = ask("URL o dominio (ej. ejemplo.com)")
            vuln_scan.check_exposed_paths(url)
        elif op == "4":
            host = ask("Host o dominio objetivo")
            vuln_scan.full_vuln_report(host)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_forense():
    while True:
        print(c("\n── FORENSE Y PRIVACIDAD DE ARCHIVOS ──", "bold"))
        print(" 1) Ver metadatos EXIF de una imagen")
        print(" 2) Limpiar metadatos EXIF (crear copia limpia)")
        print(" 3) Ocultar mensaje en imagen (esteganografía)")
        print(" 4) Extraer mensaje oculto de una imagen")
        print(" 5) Borrado seguro de archivo (sobreescritura)")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            ruta = ask("Ruta de la imagen")
            forensics.exif_viewer(ruta)
        elif op == "2":
            ruta = ask("Ruta de la imagen")
            forensics.strip_exif(ruta)
        elif op == "3":
            ruta = ask("Ruta de la imagen (PNG recomendado)")
            msg = ask("Mensaje a ocultar")
            forensics.stego_hide(ruta, msg)
        elif op == "4":
            ruta = ask("Ruta de la imagen con mensaje oculto")
            forensics.stego_extract(ruta)
        elif op == "5":
            ruta = ask("Ruta del archivo a borrar de forma segura")
            confirmar = ask(f"Esto es IRREVERSIBLE. Escribe 'SI' para borrar '{ruta}'")
            if confirmar.strip().upper() == "SI":
                forensics.secure_delete(ruta)
            else:
                info("Cancelado.")
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_webtools():
    while True:
        print(c("\n── HERRAMIENTAS WEB AVANZADAS ──", "bold"))
        print(" 1) Decodificar JWT")
        print(" 2) Analizar headers de email (detectar phishing)")
        print(" 3) Revisar robots.txt de un dominio")
        print(" 4) Chequear métodos HTTP riesgosos (PUT/DELETE/TRACE)")
        print(" 5) Generar dominios typosquatting (proteger tu marca)")
        print(" 6) Ver mi IP pública")
        print(" 7) Expandir URL acortada (ver destino real)")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            token = ask("Pega el JWT")
            webtools.jwt_decode(token)
        elif op == "2":
            info("Pega las cabeceras completas del correo. Termina con una línea vacía:")
            lineas = []
            while True:
                linea = input()
                if linea == "":
                    break
                lineas.append(linea)
            webtools.analyze_email_headers("\n".join(lineas))
        elif op == "3":
            dominio = ask("Dominio (ej. ejemplo.com)")
            webtools.robots_txt_check(dominio)
        elif op == "4":
            url = ask("URL a chequear")
            webtools.check_http_methods(url)
        elif op == "5":
            dominio = ask("Tu dominio (ej. traxer.com)")
            webtools.typosquat_generator(dominio)
        elif op == "6":
            webtools.my_public_ip()
        elif op == "7":
            url = ask("URL acortada")
            webtools.url_expander(url)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_osint_opsec():
    while True:
        print(c("\n── OSINT-OPSEC ──", "bold"))
        print(" 1) Google Dorking (genera y manda los links a la terminal)")
        print(" 2) Buscar username repetido en plataformas")
        print(" 3) Lookup de número telefónico (país/compañía/zona horaria)")
        print(" 4) Geolocalizar IP + escanear sus puertos")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            objetivo = ask("Dominio, empresa o palabra clave objetivo")
            osint_opsec.google_dorking(objetivo)
        elif op == "2":
            user = ask("Username a buscar")
            osint_opsec.username_search(user)
        elif op == "3":
            numero = ask("Número en formato internacional (ej. +525512345678)")
            osint_opsec.phone_lookup(numero)
        elif op == "4":
            ip = ask("IP objetivo")
            osint_opsec.ip_geo_and_ports(ip)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_osint():
    while True:
        print(c("\n── OSINT (RECON PASIVO) ──", "bold"))
        print(" 1) Enumerar subdominios (Certificate Transparency)")
        print(" 2) Geolocalizar IP / host")
        print(" 3) ¿Mi correo fue filtrado? (guía responsable)")
        print(" 0) Volver")
        op = ask("Elige una opción")

        if op == "1":
            dominio = ask("Dominio (ej. ejemplo.com)")
            osint.subdomain_enum(dominio)
        elif op == "2":
            host = ask("IP o host")
            osint.ip_geolocation(host)
        elif op == "3":
            email = ask("Tu correo (no se envía a ningún servidor)")
            osint.email_breach_hint(email)
        elif op == "0":
            return
        else:
            error("Opción inválida")
        pause()


def menu_principal():
    while True:
        print_banner()
        print(c("\n  MENÚ PRINCIPAL", "bold"))
        print("  1) 🌐 Red y Reconocimiento")
        print("  2) 🔐 Criptografía y Contraseñas")
        print("  3) 🕵️  OSINT (reconocimiento pasivo)")
        print("  4) 🩹 Detección de vulnerabilidades (pasiva)")
        print("  5) 🧬 Forense y privacidad de archivos")
        print("  6) 🧰 Herramientas web avanzadas")
        print("  7) 🎯 OSINT-OPSEC (dorking, username, teléfono, IP)")
        print("  8) ℹ️  Acerca de / Aviso legal")
        print("  0) 🚪 Salir")
        op = ask("Elige una opción")

        if op == "1":
            menu_red()
        elif op == "2":
            menu_cripto()
        elif op == "3":
            menu_osint()
        elif op == "4":
            menu_vulnerabilidades()
        elif op == "5":
            menu_forense()
        elif op == "6":
            menu_webtools()
        elif op == "7":
            menu_osint_opsec()
        elif op == "8":
            mostrar_acerca_de()
            pause()
        elif op == "0":
            info("¡Gracias por usar TraxerTool! Nos vemos en el canal 🎬")
            sys.exit(0)
        else:
            error("Opción inválida")


def mostrar_acerca_de():
    print(c("\nTraxerTool v1.0", "bold"))
    print("Multitool de ciberseguridad creada para la comunidad Traxer.")
    print("Solo usa librerías estándar de Python — funciona en Termux, Kali,")
    print("Debian, Ubuntu, Arch, WSL, etc. con Python 3.8+.")
    warn("\nUso ético solamente: nunca la uses contra sistemas sin autorización.")
    print("Repo: https://github.com/<tu-usuario>/TraxerTool")


if __name__ == "__main__":
    try:
        menu_principal()
    except KeyboardInterrupt:
        print()
        info("Saliendo... ¡Hasta la próxima!")
        sys.exit(0)
