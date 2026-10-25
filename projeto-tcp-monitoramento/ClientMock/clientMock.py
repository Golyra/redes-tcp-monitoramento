#!/usr/bin/env python3
"""
Cliente TCP do Sistema de Monitoramento Ambiental - DCA3605 (Unidade II).

Uso:
  python3 cliente.py                        # servidor da UFRN (10.13.123.0:54321)
  python3 cliente.py --host 127.0.0.1       # servidor simulado local
  python3 cliente.py --raw                  # mostra os bytes crus (investigação/Wireshark)
  python3 cliente.py --explorar             # terminal interativo: você digita comandos

>>> Tudo que depende do protocolo REAL está na seção "PROTOCOLO" logo abaixo.
>>> Se o servidor do professor usar outro formato, ajuste só aquela seção.
"""
import argparse
import re
import socket
import sys

# ============================ PROTOCOLO (ajustável) ============================
HOST_PADRAO = "10.13.123.0"
PORTA_PADRAO = 54321
CRLF = "\r\n"
CMD_LISTAR = "LIST"
CMD_SELECIONAR = "SELECT {id}"        # sintaxe deduzida da resposta ao LIST
SEP = "|"                             # separador de campos dos registros
FIM_LISTA = "END|LIST"                # linha que encerra a resposta do LIST
# Regex que extrai (id, nome) de cada linha de estação na resposta do LIST
RE_ESTACAO = re.compile(r"^(\d{3})\W+(.*)$")
# Tipos de registro dentro de um ciclo
REG_INICIO, REG_FIM = "BEGIN", "END"
REG_TEMP, REG_UMID, REG_PRES = "TEMP", "HUM", "PRES"
# ===============================================================================

RAW = False


class LeitorTCP:
    """
    Lê do socket e devolve UMA LINHA (terminada em CRLF) por vez.

    O TCP é um fluxo de bytes: um recv() pode trazer meia linha (fragmentação)
    ou várias linhas juntas (agrupamento). Por isso guardamos tudo em `buf`
    e só entregamos uma linha quando o CRLF aparece; o resto fica no buffer
    para a próxima chamada.
    """

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def ler_linha(self, timeout=None):
        """Devolve a próxima linha (str) ou None se estourar o timeout."""
        while b"\r\n" not in self.buf:
            self.sock.settimeout(timeout)
            try:
                dados = self.sock.recv(4096)
            except socket.timeout:
                return None
            if not dados:
                raise ConnectionError("O servidor encerrou a conexão.")
            if RAW:
                print(f"[recv {len(dados):>4} bytes] {dados!r}")
            self.buf += dados
        linha, _, self.buf = self.buf.partition(b"\r\n")
        return linha.decode("utf-8", errors="replace")


def enviar_comando(sock, cmd):
    """Envia o comando acrescentando o CRLF automaticamente."""
    sock.sendall((cmd + CRLF).encode())
    if RAW:
        print(f"[send {len(cmd) + 2:>4} bytes] {(cmd + CRLF).encode()!r}")


def listar_estacoes(sock, leitor):
    """Envia LIST e lê a resposta até o marcador de fim (ou até silêncio de 1.5 s)."""
    enviar_comando(sock, CMD_LISTAR)
    estacoes = {}
    while True:
        linha = leitor.ler_linha(timeout=1.5)
        if linha is None or linha == FIM_LISTA:
            break
        m = RE_ESTACAO.match(linha)
        if m:
            estacoes[m.group(1)] = m.group(2)
        elif RAW:
            print(f"(linha ignorada na lista: {linha!r})")
    return estacoes


def novo_ciclo(est, n):
    return {"estacao": est, "ciclo": n, "temp": None, "umid": None, "pres": None}


def processar_linha(linha, atual):
    """
    Máquina de estados simples: BEGIN abre um ciclo, TEMP/HUM/PRES o preenchem
    e END o fecha. Devolve (ciclo_em_andamento, ciclo_completo_ou_None).
    Assim nunca misturamos medições de ciclos diferentes.
    """
    campos = linha.split(SEP)
    tipo = campos[0]
    try:
        if tipo == REG_INICIO:
            return novo_ciclo(campos[1], campos[2]), None
        if atual is None:               # lixo antes de um BEGIN: ignora
            return None, None
        if tipo == REG_TEMP:
            atual["temp"] = (float(campos[1]), campos[2])
        elif tipo == REG_UMID:
            atual["umid"] = (float(campos[1]), campos[2])
        elif tipo == REG_PRES:
            atual["pres"] = (float(campos[1]), campos[2])
        elif tipo == REG_FIM:
            completo = all(atual[k] is not None for k in ("temp", "umid", "pres"))
            return None, (atual if completo else None)
    except (IndexError, ValueError):
        print(f"(registro malformado ignorado: {linha!r})")
    return atual, None


def exibir(ciclo, nome):
    if sys.stdout.isatty() and not RAW:
        print("\033[2J\033[H", end="")  # limpa a tela a cada ciclo completo
    t, u, p = ciclo["temp"], ciclo["umid"], ciclo["pres"]
    print("SISTEMA DE MONITORAMENTO AMBIENTAL")
    print("-" * 35)
    print(f" ESTACAO {ciclo['estacao']} - {nome}")
    print("-" * 35)
    print(f" Ciclo: {ciclo['ciclo']}")
    print(f" Temperatura : {t[0]:.1f} {t[1]}")
    print(f" Umidade     : {u[0]:.1f} {u[1]}")
    print(f" Pressão     : {p[0]:.1f} {p[1]}")
    print("-" * 35)
    print(" Aguardando novas medições... (Ctrl+C para sair)", flush=True)


def modo_explorar(sock, leitor):
    """Terminal cru: digite comandos, veja tudo que chegar. Ótimo p/ Atividade 1."""
    import select
    print("Modo exploração. Digite comandos (CRLF é adicionado). Ctrl+C sai.")
    while True:
        pronto, _, _ = select.select([sock, sys.stdin], [], [])
        if sock in pronto:
            dados = sock.recv(4096)
            if not dados:
                print("[conexão encerrada]")
                return
            print(f"<< {dados!r}")
        if sys.stdin in pronto:
            cmd = sys.stdin.readline().rstrip("\n")
            enviar_comando(sock, cmd)


def main():
    global RAW
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=HOST_PADRAO)
    ap.add_argument("--porta", type=int, default=PORTA_PADRAO)
    ap.add_argument("--raw", action="store_true", help="mostra bytes crus recebidos/enviados")
    ap.add_argument("--explorar", action="store_true", help="terminal interativo cru")
    a = ap.parse_args()
    RAW = a.raw

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((a.host, a.porta))
    except OSError as e:
        sys.exit(f"Não foi possível conectar a {a.host}:{a.porta} -> {e}\n"
                 "(o servidor da UFRN só é acessível pela rede da UFRN/VPN)")
    leitor = LeitorTCP(sock)

    print("SISTEMA DE MONITORAMENTO AMBIENTAL")
    print("Conectado ao servidor TCP.")

    if a.explorar:
        try:
            modo_explorar(sock, leitor)
        except KeyboardInterrupt:
            pass
        sock.close()
        return

    # Algum dado logo após conectar? (banner) — Atividade 1
    banner = leitor.ler_linha(timeout=1.0)
    if banner is not None:
        print(f"Mensagem inicial do servidor: {banner!r}")

    estacoes = listar_estacoes(sock, leitor)
    if not estacoes:
        sys.exit("Nenhuma estação reconhecida na resposta do LIST. "
                 "Use --raw / --explorar e ajuste RE_ESTACAO.")
    print("Estações disponíveis: " + ", ".join(estacoes))

    escolha = ""
    while escolha not in estacoes:
        escolha = input("Selecione uma estação: ").strip()
    enviar_comando(sock, CMD_SELECIONAR.format(id=escolha))
    print("Iniciando monitoramento...")

    atual = None
    try:
        while True:
            linha = leitor.ler_linha(timeout=None)   # bloqueia até chegar dado
            if RAW:
                print(f"  linha: {linha!r}")
            atual, completo = processar_linha(linha, atual)
            if completo:
                exibir(completo, estacoes[escolha])
    except KeyboardInterrupt:
        print("\nEncerrando...")
    except ConnectionError as e:
        print(f"\n{e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()