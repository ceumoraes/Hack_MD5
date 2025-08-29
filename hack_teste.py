import threading
import socket
import time
import hashlib
import itertools
import json
import random

PORTA_TCP = 12001
PORTA_UDP_BERKLEY = 12002
TIMEOUT = 30
CHECAGEM_COORDENADOR_INTERVALO = 5
SINC_BERKLEY_INTERVALO = 10

CONJUNTOS_MAP = {
    "digitos": "0123456789",
    "minusculas": "abcdefghijklmnopqrstuvwxyz",
    "maiusculas": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "letras": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}
CONJUNTOS = list(CONJUNTOS_MAP.keys())

def debug(clock, msg):
    print(f"[DEBUG][{clock.get()}] {msg}")

class RelogioBerkeley:
    def __init__(self):
        self.tempo = time.time() + random.randint(-30, 30)
        self.lock = threading.Lock()
    def tick(self, inc=1):
        with self.lock:
            self.tempo += inc
            return self.tempo
    def set(self, novo_tempo):
        with self.lock:
            self.tempo = novo_tempo
            return self.tempo
    def get(self):
        with self.lock:
            return float(f"{self.tempo:.2f}")

def envia_json(conn, obj):
    conn.sendall((json.dumps(obj) + '\n').encode())

def recebe_json(conn):
    linha = b''
    while True:
        ch = conn.recv(1)
        if not ch or ch == b'\n':
            break
        linha += ch
    if linha:
        return json.loads(linha.decode())
    return None

def gerar_tarefas():
    for comprimento in range(1, 5):  # até 4 caracteres
        for conjunto_nome in CONJUNTOS:
            yield (comprimento, conjunto_nome)

class Coordenador:
    def __init__(self, meu_ip, alvo_md5, lista_maquinas):
        self.meu_ip = meu_ip
        self.alvo_md5 = alvo_md5
        self.lista_maquinas = lista_maquinas[:]  # ordem de entrada
        self.trabalhadores = {}  # ip: conn
        self.tarefas = list(gerar_tarefas())
        self.senha_encontrada = None
        self.clock = RelogioBerkeley()
        self.running = True
        self.lock = threading.Lock()
        threading.Thread(target=self.servidor_tcp, daemon=True).start()
        threading.Thread(target=self.sincronismo_berkeley, daemon=True).start()

    def servidor_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', PORTA_TCP))
        sock.listen(20)
        print("[COORDENADOR] Servidor pronto.")
        while self.running:
            conn, addr = sock.accept()
            threading.Thread(target=self.handle_conn, args=(conn, addr[0]), daemon=True).start()

    def handle_conn(self, conn, ip):
        while self.running:
            try:
                req = recebe_json(conn)
                if not req: break
                cmd = req.get("cmd")
                if cmd == "REGISTRAR":
                    with self.lock:
                        self.trabalhadores[ip] = conn
                        if ip not in self.lista_maquinas:
                            self.lista_maquinas.append(ip)
                        # Propaga lista atualizada
                        self.propaga_lista()
                    envia_json(conn, {"cmd": "OK"})
                elif cmd == "PEDIR_TAREFA":
                    with self.lock:
                        if self.senha_encontrada:
                            envia_json(conn, {"cmd": "ENCERRAR", "senha": self.senha_encontrada})
                            break
                        if not self.tarefas:
                            envia_json(conn, {"cmd": "ENCERRAR", "senha": None})
                            break
                        tarefa = self.tarefas.pop(0)
                    comprimento, conjunto_nome = tarefa
                    envia_json(conn, {"cmd": "TAREFA", "comprimento": comprimento, "conjunto": conjunto_nome, "hash": self.alvo_md5})
                elif cmd == "SENHA_ENCONTRADA":
                    senha = req.get("senha")
                    print(f"[COORDENADOR] Senha encontrada: {senha}")
                    with self.lock:
                        self.senha_encontrada = senha
                        self.running = False
                    self.propagar_encerramento()
                    break
                elif cmd == "FINALIZANDO":
                    break
                elif cmd == "GET_LISTA":
                    envia_json(conn, {"cmd": "LISTA", "lista": self.lista_maquinas})
                elif cmd == "NOVO_COORDENADOR":
                    novo_ip = req.get("ip")
                    with self.lock:
                        self.running = False
                    break
            except Exception as e:
                print(f"[COORDENADOR] Erro: {e}")
                break
        with self.lock:
            self.trabalhadores.pop(ip, None)
        conn.close()

    def propaga_lista(self):
        msg = json.dumps({"cmd": "LISTA", "lista": self.lista_maquinas}).encode()
        for ip, conn in self.trabalhadores.items():
            try:
                conn.sendall(msg + b'\n')
            except: pass

    def propagar_encerramento(self):
        with self.lock:
            for conn in self.trabalhadores.values():
                try:
                    envia_json(conn, {"cmd": "ENCERRAR", "senha": self.senha_encontrada})
                except: pass
        print("[COORDENADOR] Encerramento propagado.")

    def sincronismo_berkeley(self):
        while self.running:
            time.sleep(SINC_BERKLEY_INTERVALO)
            lista = self.lista_maquinas[:]
            tempos = {self.meu_ip: self.clock.get()}
            for ip in lista:
                if ip == self.meu_ip: continue
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2)
                        s.sendto(b"GET_TIME", (ip, PORTA_UDP_BERKLEY))
                        data, _ = s.recvfrom(1024)
                        tempos[ip] = float(data.decode())
                except: pass
            if tempos:
                media = sum(tempos.values()) / len(tempos)
                self.clock.set(media)
                print(f"[BERKELEY] Média={media:.2f} Coordenador ajustou o relógio.")
                for ip in tempos.keys():
                    if ip == self.meu_ip:
                        continue
                    delta = media - tempos[ip]
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                            s.sendto(f"{delta}".encode(), (ip, PORTA_UDP_BERKLEY))
                    except: pass

class Trabalhador:
    def __init__(self, meu_ip, coord_ip):
        self.meu_ip = meu_ip
        self.coord_ip = coord_ip
        self.lista_maquinas = []
        self.running = True
        self.is_coordenador = False
        self.clock = RelogioBerkeley()
        threading.Thread(target=self.udp_berkeley, daemon=True).start()
        threading.Thread(target=self.verificar_coordenador_periodicamente, daemon=True).start()
        threading.Thread(target=self.executa, daemon=True).start()

    def atualiza_lista(self):
        try:
            sock = socket.create_connection((self.coord_ip, PORTA_TCP), timeout=5)
            envia_json(sock, {"cmd": "GET_LISTA"})
            resposta = recebe_json(sock)
            if resposta and resposta.get("cmd") == "LISTA":
                self.lista_maquinas = resposta.get("lista")
            sock.close()
        except: pass

    def verificar_coordenador_periodicamente(self):
        while self.running:
            time.sleep(CHECAGEM_COORDENADOR_INTERVALO)
            if self.is_coordenador or not self.running:
                continue
            # Tenta se comunicar com o coordenador
            try:
                with socket.create_connection((self.coord_ip, PORTA_TCP), timeout=2):
                    continue
            except Exception:
                print("[ELEIÇÃO] Coordenador caiu! Iniciando eleição...")
                self.atualiza_lista()
                self.iniciar_eleicao()

    def iniciar_eleicao(self):
        for ip in self.lista_maquinas:
            if ip == self.meu_ip:
                print("[ELEIÇÃO] Eu sou o novo coordenador!")
                self.is_coordenador = True
                self.coord_ip = self.meu_ip
                # Descobre alvo_md5 e inicia coordenador
                alvo_md5 = self.obtem_alvo_md5()
                Coordenador(self.meu_ip, alvo_md5, self.lista_maquinas)
                self.running = False
                self.anunciar_novo_coordenador()
                break
            else:
                # Tenta verificar se o ip está ativo
                try:
                    with socket.create_connection((ip, PORTA_TCP), timeout=2):
                        return  # Outro IP está ativo, será o coordenador
                except Exception:
                    continue

    def anunciar_novo_coordenador(self):
        msg = {"cmd": "NOVO_COORDENADOR", "ip": self.meu_ip}
        for ip in self.lista_maquinas:
            if ip != self.meu_ip:
                try:
                    with socket.create_connection((ip, PORTA_TCP), timeout=2) as s:
                        envia_json(s, msg)
                except: pass

    def obtem_alvo_md5(self):
        # Pergunta para os outros
        for ip in self.lista_maquinas:
            if ip == self.meu_ip: continue
            try:
                with socket.create_connection((ip, PORTA_TCP), timeout=5) as s:
                    envia_json(s, {"cmd": "GET_HASH"})
                    resposta = recebe_json(s)
                    if resposta and resposta.get("cmd") == "HASH":
                        return resposta.get("hash")
            except: pass
        return None

    def udp_berkeley(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', PORTA_UDP_BERKLEY))
        while self.running:
            try:
                data, addr = sock.recvfrom(1024)
                msg = data.decode()
                if msg == "GET_TIME":
                    sock.sendto(str(self.clock.get()).encode(), addr)
                else:
                    try:
                        delta = float(msg)
                        self.clock.set(self.clock.get() + delta)
                        print(f"[BERKELEY][{self.clock.get()}] Ajuste pelo coordenador delta={delta:.2f}")
                    except:
                        pass
            except:
                continue

    def executa(self):
        try:
            sock = socket.create_connection((self.coord_ip, PORTA_TCP), timeout=5)
            envia_json(sock, {"cmd": "REGISTRAR"})
            recebe_json(sock)
            while self.running:
                envia_json(sock, {"cmd": "PEDIR_TAREFA"})
                resposta = recebe_json(sock)
                if not resposta: break
                cmd = resposta.get("cmd")
                if cmd == "TAREFA":
                    comprimento = resposta["comprimento"]
                    conjunto_nome = resposta["conjunto"]
                    alvo_md5 = resposta["hash"]
                    conjunto = CONJUNTOS_MAP[conjunto_nome]
                    achou = self.forca_bruta(comprimento, conjunto, alvo_md5)
                    if achou:
                        envia_json(sock, {"cmd": "SENHA_ENCONTRADA", "senha": achou})
                        resposta = recebe_json(sock)
                        break
                elif cmd == "ENCERRAR":
                    senha = resposta.get("senha")
                    if senha:
                        print(f"[TRABALHADOR] Senha encontrada: {senha}")
                    else:
                        print(f"[TRABALHADOR] Encerrando, senha não encontrada.")
                    envia_json(sock, {"cmd": "FINALIZANDO"})
                    break
            sock.close()
            self.running = False
        except Exception as e:
            print(f"[TRABALHADOR] Erro conexão/execução: {e}")

    def forca_bruta(self, comprimento, conjunto, alvo_md5):
        for tup in itertools.product(conjunto, repeat=comprimento):
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            print(f"[TRABALHADOR][{self.clock.get()}] Testando '{s}' ({h})")
            if h == alvo_md5.lower():
                print(f"[TRABALHADOR][{self.clock.get()}] SENHA ENCONTRADA: {s}")
                return s
        return None

def get_meu_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def main():
    papel = input("Coordenador (c) ou Trabalhador (t)? ").strip().lower()
    meu_ip = get_meu_ip()
    if papel == 'c':
        hash_md5 = input("Digite o hash MD5 alvo: ").strip()
        print(f"Seu IP detectado: {meu_ip}")
        # Coordenador começa com lista apenas com ele
        Coordenador(meu_ip, hash_md5, [meu_ip])
        while True:
            time.sleep(1)
    elif papel == 't':
        coord_ip = input("IP do coordenador: ").strip()
        print(f"Seu IP detectado: {meu_ip}")
        Trabalhador(meu_ip, coord_ip)
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
