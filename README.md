## 🧠 ¿Cómo funciona este script?

El archivo `Analizador.py` es un script escrito en Python que automatiza el análisis forense básico de archivos en un directorio. Su objetivo principal es detectar posibles evidencias de manipulación maliciosa, amenazas encubiertas, o elementos sospechosos en los archivos, como metadatos alterados, cadenas codificadas y más.

Este es el flujo de funcionamiento del script:

1. **Verificación e instalación de herramientas necesarias**
   Antes de comenzar el análisis, el script revisa si están disponibles herramientas clave del sistema. Si alguna falta, las instala automáticamente:

   * `clamav`: para escaneo antivirus
   * `exiftool`: para leer metadatos
   * `file`: para identificar el tipo de archivo
   * `binwalk`: para detectar datos binarios ocultos o incrustados
   * `strings`: para extraer texto legible desde binarios

2. **Recorrido recursivo del directorio**
   El script recorre todos los archivos del directorio indicado (o el actual, si no se especifica ruta). A cada archivo se le aplican múltiples pruebas.

3. **Análisis por archivo**
   Para cada archivo, realiza:

   * **Detección del tipo de archivo** usando el comando `file`.
   * **Obtención de fechas de creación/modificación.**
   * **Lectura de metadatos** con `exiftool`, buscando anomalías como:

     * Fechas futuras
     * Herramientas de edición sospechosas
     * Autores marcados como "anónimo" o "desconocido"
   * **Escaneo antivirus** con ClamAV.
   * **Análisis binario** con `binwalk` para encontrar datos embebidos.
   * **Extracción de strings** con el comando `strings`, donde busca:

     * IPs, URLs, correos electrónicos
     * Contraseñas y tokens/API keys
     * Cadenas codificadas en Base64 que se decodifican automáticamente para detectar contenido como scripts, credenciales, etc.

4. **Generación de reporte**
   Todos los resultados se almacenan en el archivo `reporte_analisis.txt`, con una entrada detallada por cada archivo.

---

## ✅ Ejecución

Ejecuta el script con permisos de superusuario (necesarios para instalar herramientas si no están presentes):

```bash
sudo python3 Analizador.py --ruta /ruta/del/directorio
```

Si no se indica ninguna ruta, se analizará el directorio actual.

---

## 📂 Ejemplo de uso

```bash
sudo python3 Analizador.py --ruta /home/usuario/Descargas
```

Esto generará un archivo `reporte_analisis.txt` que incluirá, por cada archivo:

* Tipo
* Fechas
* Estado antivirus
* Metadatos extraídos y análisis
* Cadenas sospechosas encontradas
* Análisis binario

Nota: EL script debe tener permisos de ejecucion.

```bash
chmod +x Analizador.py 
```

