import os
import subprocess
import shutil
import argparse
from datetime import datetime
import re
import base64

REPORTE = "reporte_analisis.txt"

# Herramientas que suelen usarse para editar o esconder malware
HERRAMIENTAS_SOSPECHOSAS = [
    "HxD", "Hex Workshop", "Photoshop", "GIMP", "Metasploit", "vim", "Burp", "nano", "Visual Studio", "Word 2007"
]

# Patrones que indican comportamiento malicioso
PATRONES_SOSPECHOSOS = {
    "IPs": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "URLs": r"https?://[^\s]+",
    "Correos": r"[\w.-]+@[\w.-]+\.\w+",
    "Contraseñas": r"(?i)(password|passwd|clave)\s*=\s*['\"]?[\w\d!@#$%^&*()_+=\-]+['\"]?",
    "Tokens/API Keys": r"(?i)(api[_-]?key|token)\s*=\s*['\"]?[A-Za-z0-9_\-]{10,}['\"]?"
}

def instalar_si_no_existe(herramienta, paquete=None):
    if shutil.which(herramienta) is None:
        nombre_paquete = paquete if paquete else herramienta
        print(f"[+] Instalando {nombre_paquete}...")
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "install", "-y", nombre_paquete], check=True)

def obtener_tipo_archivo(path):
    try:
        return subprocess.check_output(["file", "-b", path]).decode().strip()
    except:
        return "Desconocido"

def obtener_metadatos(path):
    try:
        return subprocess.check_output(["exiftool", path], stderr=subprocess.DEVNULL).decode().strip()
    except:
        return "Error al obtener metadatos"

def analizar_virus(path):
    try:
        salida = subprocess.check_output(["clamscan", "--no-summary", path], stderr=subprocess.DEVNULL).decode()
        if "FOUND" in salida:
            return salida.strip()
        return "Sin amenazas."
    except:
        return "Error al escanear virus"

def obtener_fecha_archivo(path):
    try:
        stat = os.stat(path)
        return (
            datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        )
    except:
        return "Desconocida", "Desconocida"

def detectar_anomalias_metadatos(metadatos):
    alertas = []
    if not metadatos.strip():
        alertas.append("Metadatos vacíos o eliminados.")
    for h in HERRAMIENTAS_SOSPECHOSAS:
        if h.lower() in metadatos.lower():
            alertas.append(f"Herramienta sospechosa detectada: {h}")
    for linea in metadatos.splitlines():
        if "Date" in linea:
            partes = linea.split(": ", 1)
            if len(partes) == 2:
                try:
                    fecha = datetime.strptime(partes[1].strip(), "%Y:%m:%d %H:%M:%S")
                    if fecha > datetime.now():
                        alertas.append(f"Fecha futura en metadatos: {linea}")
                except:
                    continue
    if "Author" in metadatos or "Creator" in metadatos:
        if "anonymous" in metadatos.lower() or "unknown" in metadatos.lower():
            alertas.append("Autor marcado como anónimo o desconocido.")
    return alertas

def analizar_binwalk(path):
    try:
        salida = subprocess.check_output(["binwalk", path], stderr=subprocess.DEVNULL).decode()
        if "executable" in salida.lower() or "compressed" in salida.lower():
            return salida.strip()
        return "Sin contenido oculto."
    except:
        return "Error ejecutando binwalk."

def decodificar_base64(cadenas):
    sospechosos = []
    for cadena in cadenas:
        try:
            if 8 < len(cadena) < 300 and re.match(r'^[A-Za-z0-9+/=]{8,}$', cadena):
                decodificado = base64.b64decode(cadena + "==", validate=True)
                texto = decodificado.decode('utf-8', errors='ignore')
                if any(palabra in texto.lower() for palabra in ["password", "admin", "cmd", "powershell", "bash"]):
                    sospechosos.append(f"Base64 detectado y decodificado: {texto.strip()}")
        except:
            continue
    return sospechosos

def buscar_strings_sospechosos(path):
    try:
        salida = subprocess.check_output(["strings", path], stderr=subprocess.DEVNULL).decode(errors="ignore")
        encontrados = []
        base64_candidatos = []
        for tipo, patron in PATRONES_SOSPECHOSOS.items():
            coincidencias = re.findall(patron, salida, flags=re.IGNORECASE)
            if coincidencias:
                encontrados += [f"{tipo}: {c}" for c in coincidencias]
        base64_candidatos += re.findall(r"[A-Za-z0-9+/=]{8,}", salida)
        sospechosos_base64 = decodificar_base64(set(base64_candidatos))
        return list(set(encontrados + sospechosos_base64)) if encontrados or sospechosos_base64 else ["Ninguna cadena sospechosa."]
    except:
        return ["Error ejecutando strings."]

def analizar_archivos(directorio):
    with open(REPORTE, "w", encoding="utf-8") as reporte:
        for root, _, files in os.walk(directorio):
            for archivo in files:
                ruta = os.path.join(root, archivo)
                print(f"[+] Analizando: {ruta}")
                try:
                    tipo = obtener_tipo_archivo(ruta)
                    fecha_creacion, fecha_mod = obtener_fecha_archivo(ruta)
                    metadatos = obtener_metadatos(ruta)
                    virus = analizar_virus(ruta)
                    alertas_meta = detectar_anomalias_metadatos(metadatos)
                    binwalk_info = analizar_binwalk(ruta)
                    strings_sospechosos = buscar_strings_sospechosos(ruta)

                    reporte.write(f"Archivo: {ruta}\n")
                    reporte.write(f"Tipo: {tipo}\n")
                    reporte.write(f"Fecha creación: {fecha_creacion}\n")
                    reporte.write(f"Fecha modificación: {fecha_mod}\n")
                    reporte.write(f"Estado Antivirus: {virus}\n")
                    
                    if alertas_meta:
                        reporte.write("ALERTAS DE METADATOS:\n" + "\n".join(alertas_meta) + "\n")
                    
                    reporte.write("Binwalk:\n" + binwalk_info + "\n")
                    reporte.write("Strings sospechosos:\n" + "\n".join(strings_sospechosos) + "\n")
                    reporte.write("Metadatos:\n" + metadatos + "\n")
                    reporte.write("-" * 100 + "\n")

                except Exception as e:
                    reporte.write(f"Error analizando {ruta}: {str(e)}\n")
                    reporte.write("-" * 100 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Análisis forense y antivirus de archivos")
    parser.add_argument("--ruta", type=str, help="Ruta del directorio a analizar", default=".")
    args = parser.parse_args()

    print("[*] Verificando herramientas necesarias...")
    instalar_si_no_existe("clamav")
    instalar_si_no_existe("exiftool")
    instalar_si_no_existe("file")
    instalar_si_no_existe("binwalk")
    instalar_si_no_existe("strings", "binutils")

    print(f"[*] Iniciando análisis en: {args.ruta}")
    analizar_archivos(args.ruta)
    print(f"\n[✓] Análisis finalizado. Revisa el archivo: {REPORTE}")
