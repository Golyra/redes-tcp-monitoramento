#!/usr/bin/env python3
"""
Servidor TCP SIMULADO do sistema de monitoramento ambiental (DCA3605).

ATENÇÃO: o protocolo real do professor é desconhecido. Este servidor
implementa um protocolo PLAUSÍVEL só para você testar o cliente em casa.
Quando estiver na rede da UFRN, descubra o formato real (modo --raw do cliente
+ Wireshark) e ajuste as constantes/funções de parsing do cliente.

Protocolo simulado (todas as linhas terminam em CRLF):
  ao conectar : WELCOME|ENV-MONITOR|1.0
  cliente->   : LIST
  <-servidor  : STATIONS|3
                001;NORTE
                002;CENTRO
                003;SUL
                END|LIST
  cliente->   : SELECT 002
  <-servidor  : OK|SELECT|002
  e, a cada INTERVALO segundos, um ciclo:
                BEGIN|002|5
                TEMP|28.7|C
                HUM|74.6|%
                PRES|1011.3|hPa
                END|002|5

Uso:
  python3 servidor_mock.py                    # porta 54321, ciclo a cada 5 s
  python3 servidor_mock.py --intervalo 2
  python3 servidor_mock.py --caos             # fragmenta/agrupa os bytes (testa o buffer!)
"""
import argparse
import random
import socket
import threading
import time

ESTACOES = {"001": "NORTE", "002": "CENTRO", "003": "SUL"}
CRLF = "\r\n"


def montar_ciclo(est, n, estado):
    """Gera os bytes de um ciclo completo para a estação `est`."""
    t, u, p = estado
    # pequeno passeio aleatório para os valores variarem de forma realista
    t += random.uniform(-0.4, 0.4)
    u = min(100, max(0, u + random.uniform(-1.0, 1.0)))
    p += random.uniform(-0.3, 0.3)
    estado[:] = [t, u, p]
    linhas = [
        f"BEGIN|{est}|{n}",
        f"TEMP|{t:.1f}|C",
        f"HUM|{u:.1f}|%",
        f"PRES|{p:.1f}|hPa",
        f"END|{est}|{n}",
    ]
    return "".join(l + CRLF for l in linhas).encode()


def enviar(conn, dados, caos):
    """Envia bytes; no modo caos, corta em pedaços aleatórios (fragmentação)."""
    if not caos:
        conn.sendall(dados)
        return
    i = 0
    while i < len(dados):
        k = random.randint(1, 12)
        conn.sendall(dados[i:i + k])
        i += k
        time.sleep(random.uniform(0.0, 0.05))


def transmissor(conn, est, intervalo, caos, parar):
    """Thread que envia ciclos periodicamente pela MESMA conexão."""
    estado = [random.uniform(24, 32), random.uniform(55, 85), random.uniform(1005, 1018)]
    n = 1
    while not parar.is_set():
        try:
            ciclo = montar_ciclo(est, n, estado)
            if caos and random.random() < 0.3:
                # agrupa: manda este ciclo e o próximo colados num único send
                n += 1
                ciclo += montar_ciclo(est, n, estado)
                conn.sendall(ciclo)
            else:
                enviar(conn, ciclo, caos)
        except OSError:
            return
        n += 1
        parar.wait(intervalo)


def atender(conn, addr, intervalo, caos):
    print(f"[+] conexão de {addr}")
    parar = threading.Event()
    buf = b""
    try:
        conn.sendall(f"WELCOME|ENV-MONITOR|1.0{CRLF}".encode())
        while True:
            dados = conn.recv(1024)
            if not dados:
                break
            buf += dados
            while b"\r\n" in buf:  # delimita comandos por CRLF
                linha, _, buf = buf.partition(b"\r\n")
                cmd = linha.decode(errors="replace").strip()
                print(f"    {addr} -> {cmd!r}")
                partes = cmd.split()
                if not partes:
                    continue
                if partes[0].upper() == "LIST":
                    resp = f"STATIONS|{len(ESTACOES)}{CRLF}"
                    resp += "".join(f"{k};{v}{CRLF}" for k, v in ESTACOES.items())
                    resp += f"END|LIST{CRLF}"
                    conn.sendall(resp.encode())
                elif partes[0].upper() == "SELECT" and len(partes) == 2 and partes[1] in ESTACOES:
                    conn.sendall(f"OK|SELECT|{partes[1]}{CRLF}".encode())
                    parar.set()            # encerra transmissão anterior, se houver
                    parar = threading.Event()
                    threading.Thread(target=transmissor,
                                     args=(conn, partes[1], intervalo, caos, parar),
                                     daemon=True).start()
                elif partes[0].upper() == "QUIT":
                    return
                else:
                    conn.sendall(f"ERR|comando invalido{CRLF}".encode())
    except OSError:
        pass
    finally:
        parar.set()
        conn.close()
        print(f"[-] {addr} desconectou")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--porta", type=int, default=54321)
    ap.add_argument("--intervalo", type=float, default=5.0, help="segundos entre ciclos")
    ap.add_argument("--caos", action="store_true", help="fragmenta e agrupa os dados")
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.host, a.porta))
    srv.listen()
    print(f"Servidor simulado em {a.host}:{a.porta} (intervalo={a.intervalo}s, caos={a.caos})")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=atender, args=(conn, addr, a.intervalo, a.caos), daemon=True).start()


if __name__ == "__main__":
    main()