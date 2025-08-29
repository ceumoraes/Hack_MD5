import socket
import threading
import itertools
import hashlib
import json
import time
import random

PORT = 12001
PORT_UDP_BERKELEY = 12002
BUFFER = 4096

CONJUNTOS_MAP = {
    "digitos": "0123456789",
    "minusculas": "abcdefghijklmnopqrstuvwxyz",
    "maiusculas": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "letras": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
}
CONJUNTOS = list(CONJUNTOS_MAP.keys())

def gerar_tarefas():
    for comprimento in range(1, 5):  # Teste até senhas de 4 caracteres
        for conjunto_nome in CONJUNTOS:
            yield (comprimento, conjunto_nome)

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

class Coordenador:
    def __init__(self, alvo_md5):
        self.alvo_md5 = alvo_md5
        self.trabalhadores = {}  # ip: conn
        self.tarefas = list(gerar_tarefas())
        self.tarefas_status = {}  # ip: tarefa atual
        self.senha_encontrada = None
        self.lock = threading.Lock()
        self.running = True
        self.clock = RelogioBerkeley()
        threading.Thread(target=self.servidor, daemon=True).start()
        threading.Thread(target=self.sincronismo_berkeley, daemon=True).start()

    def servidor(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', PORT))
        sock.listen(20)
        print("[COORDENADOR] Servidor pronto.")
        while self.running:
            conn, addr = sock.accept()
            threading.Thread(target=self.handle, args=(conn, addr[0]), daemon=True).start()

    def handle(self, conn, ip):
        print(f"[COORDENADOR] Conexão de {ip}")
        while self.running:
            try:
                req = recebe_json(conn)
                if not req: break
                cmd = req.get("cmd")
                if cmd == "REGISTRAR":
                    with self.lock:
                        self.trabalhadores[ip] = conn
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
                        self.tarefas_status[ip] = tarefa
                    comprimento, conjunto_nome = tarefa
                    envia_json(conn, {"cmd": "TAREFA", "comprimento": comprimento, "conjunto": conjunto_nome, "hash": self.alvo_md5})
                elif cmd == "SENHA_ENCONTRADA":
                    senha = req.get("senha")
                    print(f"[COORDENADOR] Senha encontrada: {senha}")
                    with self.lock:
                        self.senha_encontrada = senha
                    self.propagar_encerramento()
                    break
                elif cmd == "FINALIZANDO":
                    break
            except Exception as e:
                print(f"[COORDENADOR] Erro: {e}")
                break
        with self.lock:
            self.trabalhadores.pop(ip, None)
            self.tarefas_status.pop(ip, None)
        conn.close()

    def propagar_encerramento(self):
        with self.lock:
            for conn in self.trabalhadores.values():
                try:
                    envia_json(conn, {"cmd": "ENCERRAR", "senha": self.senha_encontrada})
                except:
                    pass
            self.running = False
        print("[COORDENADOR] Encerramento propagado.")

    def sincronismo_berkeley(self):
        while self.running:
            time.sleep(10)
            lista = list(self.trabalhadores.keys())
            tempos = { "coordenador": self.clock.get() }
            # coleta os tempos dos trabalhadores via UDP
            for ip in lista:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2)
                        s.sendto(b"GET_TIME", (ip, PORT_UDP_BERKELEY))
                        data, _ = s.recvfrom(1024)
                        tempos[ip] = float(data.decode())
                except:
                    pass
            if tempos:
                media = sum(tempos.values()) / len(tempos)
                # Ajusta o próprio relógio
                self.clock.set(media)
                print(f"[BERKELEY] Média={media:.2f} Coordenador ajustou o relógio.")
                # Envia delta para trabalhadores
                for ip in lista:
                    if ip in tempos:
                        delta = media - tempos[ip]
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                s.sendto(f"{delta}".encode(), (ip, PORT_UDP_BERKELEY))
                        except:
                            pass

class Trabalhador:
    def __init__(self, coord_ip):
        self.coord_ip = coord_ip
        self.running = True
        self.clock = RelogioBerkeley()
        threading.Thread(target=self.udp_berkeley, daemon=True).start()
        self.socket = socket.create_connection((coord_ip, PORT))
        envia_json(self.socket, {"cmd": "REGISTRAR"})
        recebe_json(self.socket)
        threading.Thread(target=self.executa, daemon=True).start()

    def executa(self):
        while self.running:
            envia_json(self.socket, {"cmd": "PEDIR_TAREFA"})
            resposta = recebe_json(self.socket)
            if not resposta: break
            cmd = resposta.get("cmd")
            if cmd == "TAREFA":
                comprimento = resposta["comprimento"]
                conjunto_nome = resposta["conjunto"]
                alvo_md5 = resposta["hash"]
                conjunto = CONJUNTOS_MAP[conjunto_nome]
                achou = self.forca_bruta(comprimento, conjunto, alvo_md5)
                if achou:
                    envia_json(self.socket, {"cmd": "SENHA_ENCONTRADA", "senha": achou})
                    resposta = recebe_json(self.socket)
                    break
            elif cmd == "ENCERRAR":
                senha = resposta.get("senha")
                if senha:
                    print(f"[TRABALHADOR] Senha encontrada: {senha}")
                else:
                    print(f"[TRABALHADOR] Encerrando, senha não encontrada.")
                envia_json(self.socket, {"cmd": "FINALIZANDO"})
                break
        self.socket.close()
        self.running = False

    def forca_bruta(self, comprimento, conjunto, alvo_md5):
        for tup in itertools.product(conjunto, repeat=comprimento):
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            print(f"[TRABALHADOR][{self.clock.get()}] Testando '{s}' ({h})")
            if h == alvo_md5.lower():
                print(f"[TRABALHADOR][{self.clock.get()}] SENHA ENCONTRADA: {s}")
                return s
        return None

    def udp_berkeley(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', PORT_UDP_BERKELEY))
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

def main():
    papel = input("Coordenador (c) ou Trabalhador (t)? ").strip().lower()
    if papel == 'c':
        alvo_md5 = input("Digite o hash MD5 alvo: ").strip()
        Coordenador(alvo_md5)
        while True:
            time.sleep(1)
    elif papel == 't':
        coord_ip = input("IP do coordenador: ").strip()
        Trabalhador(coord_ip)
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
