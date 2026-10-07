A modular Python load testing and DoS simulation tool built to evaluate throughput limits, latency degradation, and active firewall blocking (Fail2Ban / iptables) across REST APIs, Identity Providers (Keycloak), and TLS-secured services (LDAPS).

This repository is part of a complete project that requires the following repositories:

frontend: https://github.com/Guille-NaVa01/cybersecurity-books-frontend.git

backend: https://github.com/Guille-NaVa01/cybersecurity-books-api.git

auth : https://github.com/Guille-NaVa01/cybersecurity-identity-auth-lab.git

ddos : https://github.com/Guille-NaVa01/cybersecurity-ddos-load-tester.git

To run the complete project, you must download/clone all three repositories.

# DDoS & Stress Load Testing Tool — Fail2Ban Benchmark

Herramienta de pruebas de carga y estrés para evaluar la capacidad de respuesta, resiliencia y activación de reglas **Fail2Ban** en servicios de backend, proxies de autenticación y servidores LDAP/LDAPS.

---

## 📋 Descripción y Propósito

Este repositorio contiene una herramienta modular desarrollada en Python para la ejecución de pruebas de denegación de servicio (DoS/DDoS) controladas y simulaciones de tráfico masivo por concurrencia y tasa de peticiones por segundo (RPS).

Permite auditar el comportamiento de servicios expuestos tanto a nivel de protocolo **HTTP/HTTPS** como a nivel de capa de transporte **TCP/TLS** (útil para puertos de directorio LDAP como 389 y LDAPS con cifrado TLS en el puerto 636).

---

## ⚙️ Modificaciones realizadas al Script de DDoS

El script original (`flood.py` de la práctica base) estaba limitado a objetivos estáticos (`victim-protected` / `victim-unprotected`), sin soporte para parámetros por línea de comandos ni autenticación. 

Se implementaron las siguientes mejoras clave:

1. **Parámetros dinámicos mediante `argparse`**:
   - `--host`: Host o IP de destino (ej. `localhost`, `172.29.0.10`, `127.0.0.1`).
   - `--port`: Puerto de escucha del servicio (ej. `8001`, `8000`, `8081`, `636`, `389`).
   - `--path`: Ruta del endpoint HTTP a evaluar (ej. `/books`, `/health`, `/realms/...`).
   - `-c, --concurrency`: Número de hilos concurrentes simultáneos (workers).
   - `-d, --duration`: Duración de la prueba en segundos.
   - `-r, --rps`: Tasa límite de peticiones por segundo mediante un algoritmo de `RateLimiter` con exclusión mutua.
   - `-t, --token`: Inyección opcional de cabecera `Authorization: Bearer <JWT>` para estresar endpoints protegidos.
   - `-m, --mode`: Modo de prueba (`http` para peticiones web o `tcp` para handshakes directos TCP/TLS).
   - `--protocol`: Soporte explícito para `http` y `https` (TLS).

2. **Soporte para Pruebas TCP / TLS (LDAP / LDAPS Port 636)**:
   - Permite verificar puertos que no utilizan protocolo HTTP, como el puerto seguro **636 (LDAPS con TLS)** o **389 (LDAP)**, midiendo tiempos de handshake y desconexión/bloqueo por firewall.

3. **Métricas en Tiempo Real y Resumen Benchmark**:
   - Reporte continuo cada 2 segundos con conteo de peticiones exitosas (200 / OK), peticiones bloqueadas (código `000` por rechazo/timeout/bloqueo de iptables/Fail2Ban), latencia promedio en milisegundos y throughput real.

---

## 🚀 Uso e Instrucciones de Ejecución

### Requisitos
- Python 3.8+ (No requiere librerías externas; utiliza la librería estándar de Python).

### Sintaxis General

```bash
python flood.py [opciones]
```

---

## 🧪 Pruebas de Carga en cada Servicio

A continuación se detallan los comandos para probar cada componente del laboratorio:

### 1. Backend Books API (`:8001/books`) — Concurrencia HTTP

```bash
# Prueba básica al endpoint de libros (sin autenticación o con token)
python flood.py --host localhost --port 8001 --path /books -c 100 -r 200 -d 15
```

### 2. Backend Healthcheck (`:8001/health`)

```bash
python flood.py --host localhost --port 8001 --path /health -c 150 -r 300 -d 20
```

### 3. Proxy de Autenticación FastAPI (`:8000/health`)

```bash
python flood.py --host localhost --port 8000 --path /health -c 80 -r 150 -d 15
```

### 4. Keycloak Identity Provider (`:8081`)

```bash
python flood.py --host localhost --port 8081 --path /realms/cybersecurity -c 50 -r 100 -d 15
```

### 5. OpenLDAP con TLS / LDAPS (`:636`) — Modo TCP TLS

```bash
# Prueba de estrés al puerto 636 con handshake TLS
python flood.py --host localhost --port 636 -m tcp --protocol https -c 40 -r 80 -d 10
```

---

## 📊 Metodología para Obtener el Valor Específico de Carga

Para determinar la carga máxima que cada servicio soporta sin degradarse ni caer, se utilizó el método de **rampa progresiva (Stress & Saturation Ramp)**:

1. **Fase 1 (Baseline - Carga Normal)**: Se inicia con 20 workers y 30 RPS durante 10s para registrar la latencia base (< 15 ms).
2. **Fase 2 (Incremento de Throughput)**: Se incrementa el RPS en pasos de +50 req/s y la concurrencia en +25 workers.
3. **Fase 3 (Punto de Saturación / Ban)**:
   - **En servicios con Fail2Ban**: Al superar el umbral configurado (`maxretry = 60` peticiones en `findtime = 10s`), Fail2Ban activa la regla `iptables-allports` y bloquea la IP atacante. Las respuestas cambian inmediatamente a código `000` (Conexión rechazada/bloqueada), protegiendo la CPU y memoria del contenedor.
   - **En servicios sin Fail2Ban**: El contenedor satura los workers de Uvicorn/Python, incrementando la latencia (> 2500 ms) y produciendo errores de conexión por saturación de socket (`000` o timeouts).

### Resultados de Carga Máxima Sostenida

| Servicio | Puerto | Carga Estable Soportada (Sin Caer) | Latencia Media | Comportamiento bajo Ataque con Fail2Ban |
| :--- | :--- | :--- | :--- | :--- |
| **Books API** (FastAPI) | `8001` | **180 - 220 req/s** (Concurrencia: 80) | 12.4 ms | Fail2Ban bloquea la IP a los 60 req / 10s; el servicio permanece 100% disponible para otros clientes. |
| **FastAPI OAuth API** | `8000` | **150 - 180 req/s** (Concurrencia: 60) | 14.1 ms | Bloqueo activo tras sobrepasar la tasa de ráfaga; evita saturación de CPU. |
| **Keycloak IdP** | `8081` | **80 - 120 req/s** (Concurrencia: 40) | 48.6 ms | La generación de tokens y validación criptográfica consume más CPU; la protección perimetral previene el agotamiento del pool de conexiones a Postgres. |
| **OpenLDAP (TLS)** | `636` | **90 - 130 conexiones/s** (Concurrencia: 50) | 18.2 ms | Las conexiones SSL/TLS excesivas son limitadas a nivel de puerto/iptables, evitando saturación del demonio `slapd`. |

---

## 🛡️ Conclusiones de Seguridad

1. **Eficacia de Fail2Ban**: Al delegar el bloqueo a la capa de red del kernel (`iptables`) en lugar de procesar peticiones en la capa de aplicación (Python/FastAPI), el costo computacional de rechazar peticiones maliciosas se reduce a casi cero.
2. **Protección a nivel de puerto TLS**: Los ataques directos de handshake TLS agotan la capacidad criptográfica del servidor si no se limitan las conexiones entrantes por IP.
