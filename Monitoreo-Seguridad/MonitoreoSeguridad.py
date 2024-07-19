from scapy.all import rdpcap
from collections import Counter
import csv
import matplotlib.pyplot as plt

# Definir el archivo PCAP
archivo_pcap = r"c:\Users\aless\Desktop\CapturaWireshark.pcapng"

# Leer el archivo PCAP
try:
    packets = rdpcap(archivo_pcap)
except FileNotFoundError:
    print(f"Error: No se pudo encontrar el archivo {archivo_pcap}")
    exit()
except Exception as e:
    print(f"Error al leer el archivo {archivo_pcap}: {e}")
    exit()

# Contar intentos de conexión por IP
ip_counts = Counter(packet[1].src for packet in packets if packet.haslayer('IP'))

# Generar alertas para IPs con intentos de conexión superiores a 10
for ip, count in ip_counts.items():
    if count > 10:  # Umbral de alerta
        print(f'Alerta: IP {ip} ha intentado conectarse {count} veces')

# Escribir los resultados en un archivo CSV
csv_filename = 'reporte.csv'
try:
    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Intentos']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for ip, count in ip_counts.items():
            writer.writerow({'IP': ip, 'Intentos': count})
    print(f'Reporte CSV guardado en {csv_filename}')
except Exception as e:
    print(f"Error al escribir el archivo CSV: {e}")

# Crear gráfico de barras
try:
    ips = list(ip_counts.keys())
    counts = list(ip_counts.values())

    plt.figure(figsize=(10, 5))  # Ajustar tamaño del gráfico
    plt.bar(ips, counts)
    plt.xlabel('IP')
    plt.ylabel('Intentos de Conexión')
    plt.title('Intentos de Conexión por IP')
    plt.xticks(rotation=90)
    plt.tight_layout()  # Ajustar el diseño para que todo se vea bien
    plt.show()
except Exception as e:
    print(f"Error al generar el gráfico: {e}")
