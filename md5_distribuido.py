"""
IFBA - Projeto Final de Sistemas Distribuídos
Brute Force MD5 Distribuído com:
- Exclusão Mútua Ricart-Agrawala (TCP)
- Relógios Lógicos Lamport
- Lista dinâmica de máquinas
- Sincronização de Relógios Berkley (UDP)
- Delegação dinâmica de tarefas brute force

Autores: [Seu Nome]
Data: [Data de Criação]

Como rodar:
1. Inicie pelo menos um nó como coordenador.
2. Outros nós podem se conectar indicando coordenador.
3. O sistema distribui as tarefas de brute force conforme novas máquinas entram.

Requisitos:
- Python 3.7+
- Rede TCP/UDP liberada nas portas indicadas

"""

import threading
import socket
import time
import hashlib
import itertools
import json
import random

# ========== CONFIGURAÇÕES ==========
PORTA_TCP = 12001
PORTA_UDP_BERKLEY = 12002
TIMEOUT = 30

CONJUNTOS = {
    "digitos": "0123456789",
    "minusculas": "abcdefghijklmnopqrstuvwxyz",
    "maiusculas": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "letras": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "minusculasdigitos": "abcdefghijklmnopqrstuvwxyz0123456789",
    "imprimiveis": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

# ========== RELÓGIO LÓGICO LAMPORT ==========
class LamportClock:
    def __init__(self):
        self.timestamp = random.randint(0, 100)

    def tick(self):
        self.timestamp += 1
        return self.timestamp

    def update(self, received):
        self.timestamp = max(self.timestamp, received) + 1
        return self.timestamp

    def get(self):
        return self.timestamp

# ========== BERKLEY ==========
class BerkleySync(threading.Thread):
    def __init__(self, lista_maquinas, is_coordenador, lamport_clock, tempo_local_fn):
        super().__init__(daemon=True)
        self.lista_maquinas = lista_maquinas
        self.is_coordenador = is_coordenador
        self.lamport = lamport_clock
        self.tempo_local_fn = tempo_local_fn
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('', PORTA_UDP_BERKLEY))

    def run(self):
        while True:
            if self.is_coordenador():
                self._coordenador_berkley()
            else:
                self._participante_berkley()
            time.sleep(15)

    def _coordenador_berkley(self):
        tempos = []
        for ip in self.lista_maquinas():
            if ip == self._get_meu_ip():
                continue
            try:
                msg = json.dumps({"cmd": "BERKLEY_REQUEST", "clock": self.lamport.get()}).encode()
                self.sock.sendto(msg, (ip, PORTA_UDP_BERKLEY))
            except Exception:
                pass
        self.sock.settimeout(2)
        tempos.append(self.tempo_local_fn())
        start = time.time()
        while time.time() - start < 2:
            try:
                dados, addr = self.sock.recvfrom(1024)
                info = json.loads(dados.decode())
                if info.get("cmd") == "BERKLEY_RESPONSE":
                    tempos.append(info["tempo"])
            except socket.timeout:
                break
            except Exception:
                continue
        if tempos:
            novo_tempo = sum(tempos) / len(tempos)
            for ip in self.lista_maquinas():
                if ip == self._get_meu_ip():
                    continue
                try:
                    msg = json.dumps({"cmd": "BERKLEY_SET", "novo_tempo": novo_tempo}).encode()
                    self.sock.sendto(msg, (ip, PORTA_UDP_BERKLEY))
                except Exception:
                    pass
            self._set_tempo_local(novo_tempo)

    def _participante_berkley(self):
        self.sock.settimeout(3)
        try:
            dados, addr = self.sock.recvfrom(1024)
            info = json.loads(dados.decode())
            if info.get("cmd") == "BERKLEY_REQUEST":
                msg = json.dumps({"cmd": "BERKLEY_RESPONSE", "tempo": self.tempo_local_fn()}).encode()
                self.sock.sendto(msg, addr)
            elif info.get("cmd") == "BERKLEY_SET":
                self._set_tempo_local(info["novo_tempo"])
        except socket.timeout:
            pass
        except Exception:
            pass

    def _get_meu_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _set_tempo_local(self, novo_tempo):
        print(f"[BERKLEY] Tempo ajustado para {novo_tempo:.2f}")

# ========== RICART-AGRAWALA ==========
class RicartAgrawala:
    def __init__(self, meu_id, lista_maquinas_fn, lamport_clock):
        self.meu_id = meu_id
        self.lista_maquinas_fn = lista_maquinas_fn
        self.lamport = lamport_clock
        self.req_timestamp = None
        self.deferred = []
        self.ack_event = threading.Event()
        self.recebidos = set()
        self.lock = threading.Lock()

    def pedir_regiao_critica(self):
        with self.lock:
            self.req_timestamp = self.lamport.tick()
            self.recebidos = set()
            self.ack_event.clear()
        lista = self.lista_maquinas_fn()
        for ip in lista:
            if ip == self.meu_id:
                continue
            try:
                msg = json.dumps({"cmd": "REQUEST", "timestamp": self.req_timestamp, "from": self.meu_id}).encode()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TIMEOUT)
                s.connect((ip, PORTA_TCP))
                s.sendall(msg)
                s.close()
            except Exception:
                continue
        wait_time = 15
        start = time.time()
        while True:
            with self.lock:
                if self.recebidos >= set([ip for ip in lista if ip != self.meu_id]):
                    break
            if time.time() - start > wait_time:
                print("[RA] Timeout esperando ACKs")
                break
            time.sleep(0.2)

    def receber_msg(self, info):
        cmd = info.get("cmd")
        ts = info.get("timestamp", 0)
        sender = info.get("from")
        if cmd == "REQUEST":
            with self.lock:
                self.lamport.update(ts)
                if (self.req_timestamp is None or
                    ts < self.req_timestamp or
                    (ts == self.req_timestamp and sender < self.meu_id)):
                    try:
                        msg = json.dumps({"cmd": "REPLY", "timestamp": self.lamport.tick(), "from": self.meu_id}).encode()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(TIMEOUT)
                        s.connect((sender, PORTA_TCP))
                        s.sendall(msg)
                        s.close()
                    except Exception:
                        pass
                else:
                    self.deferred.append(sender)
        elif cmd == "REPLY":
            with self.lock:
                self.lamport.update(ts)
                self.recebidos.add(sender)

    def liberar_regiao_critica(self):
        with self.lock:
            for ip in self.deferred:
                try:
                    msg = json.dumps({"cmd": "REPLY", "timestamp": self.lamport.tick(), "from": self.meu_id}).encode()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    s.connect((ip, PORTA_TCP))
                    s.sendall(msg)
                    s.close()
                except Exception:
                    pass
            self.deferred = []
            self.req_timestamp = None

# ========== GERÊNCIA DE LISTA DE MÁQUINAS & TAREFAS ==========
class GerenteDistribuido:
    def __init__(self, meu_ip):
        self.meu_ip = meu_ip
        self.lista_maquinas = [meu_ip]
        self.tarefas = {}
        self.lock = threading.Lock()

    def adicionar_maquina(self, ip):
        with self.lock:
            if ip not in self.lista_maquinas:
                self.lista_maquinas.append(ip)
                print(f"[MAQUINAS] Adicionada máquina {ip}")

    def remover_maquina(self, ip):
        with self.lock:
            if ip in self.lista_maquinas:
                self.lista_maquinas.remove(ip)
                print(f"[MAQUINAS] Removida máquina {ip}")
            if ip in self.tarefas:
                del self.tarefas[ip]

    def replicar_lista(self, destino_ip):
        try:
            msg = json.dumps({"cmd": "LISTA_MAQUINAS", "lista": self.lista_maquinas}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((destino_ip, PORTA_TCP))
            s.sendall(msg)
            s.close()
        except Exception:
            pass

    def atualizar_lista(self, nova_lista):
        with self.lock:
            self.lista_maquinas = list(nova_lista)
            print(f"[MAQUINAS] Lista atualizada: {self.lista_maquinas}")

    def delegar_tarefa(self, ip):
        with self.lock:
            usados = set(self.tarefas.values())
            comprimento = 1
            while comprimento in usados:
                comprimento += 1
            self.tarefas[ip] = comprimento
            return comprimento

    def finalizar_tarefa(self, ip):
        with self.lock:
            if ip in self.tarefas:
                self.tarefas[ip] += 1

    def get_lista_maquinas(self):
        with self.lock:
            return list(self.lista_maquinas)

    def get_tarefas(self):
        with self.lock:
            return dict(self.tarefas)

# ========== BRUTE FORCE MD5 ==========
class BruteForceMD5(threading.Thread):
    def __init__(self, meu_ip, gerente, lamport, alvo_hash, conjuntos, on_found):
        super().__init__(daemon=True)
        self.meu_ip = meu_ip
        self.gerente = gerente
        self.lamport = lamport
        self.alvo_hash = alvo_hash
        self.conjuntos = conjuntos
        self.on_found = on_found
        self.sair = False

    def run(self):
        while self.alvo_hash is None:
            time.sleep(0.5)
        while not self.sair:
            comprimento = self.gerente.delegar_tarefa(self.meu_ip)
            print(f"[BF] Começando brute force comprimento={comprimento}")  # <-- Apenas uma vez por tarefa!
            for nome_conjunto in self.conjuntos:
                if self.sair:
                    break
                conjunto = CONJUNTOS[nome_conjunto]
                achou = self._forca_bruta(comprimento, conjunto)
                if achou:
                    self.on_found(achou)
                    self.sair = True
                    break
            if not self.sair:
                self.gerente.finalizar_tarefa(self.meu_ip)

    def _forca_bruta(self, comprimento, conjunto):
        alvo = self.alvo_hash.lower()
        for tup in itertools.product(conjunto, repeat=comprimento):
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            print(f"\033[2K\r[BF] Testando: {s}", end="", flush=True)
            if h == alvo:
                print(f"\n[BF] SENHA ENCONTRADA: '{s}' para comprimento={comprimento} e conjunto {conjunto}")
                return s
        print("\033[2K\r", end="")
        return None

# ========== SERVIDOR PRINCIPAL ==========
class ServidorDistribuido:
    def __init__(self, meu_ip, coordenador_ip, alvo_md5):
        self.meu_ip = meu_ip
        self.coordenador_ip = coordenador_ip
        self.alvo_md5 = alvo_md5
        self.lamport = LamportClock()
        self.gerente = GerenteDistribuido(meu_ip)
        self.ricart = RicartAgrawala(meu_ip, self.gerente.get_lista_maquinas, self.lamport)
        self.senha_encontrada = None
        self.sair = False

        self.berkley = BerkleySync(
            lista_maquinas=self.gerente.get_lista_maquinas,
            is_coordenador=lambda: self.gerente.get_lista_maquinas()[0] == self.meu_ip,
            lamport_clock=self.lamport,
            tempo_local_fn=lambda: time.time(),
        )
        self.berkley.start()

        if self.meu_ip != coordenador_ip:
            self.conectar_ao_sistema()
            while self.alvo_md5 is None:
                time.sleep(0.5)

        # Apenas trabalhador executa brute force
        if self.meu_ip != self.coordenador_ip:
            conjuntos = ["digitos", "minusculas", "maiusculas", "letras", "minusculasdigitos", "imprimiveis"]
            self.brute_force = BruteForceMD5(
                meu_ip=self.meu_ip,
                gerente=self.gerente,
                lamport=self.lamport,
                alvo_hash=self.alvo_md5,
                conjuntos=conjuntos,
                on_found=self._on_password_found,
            )
            self.brute_force.start()

        threading.Thread(target=self._servidor_tcp, daemon=True).start()

    def conectar_ao_sistema(self):
        print(f"[CONEXAO] Solicitando entrada no sistema...")
        self.ricart.pedir_regiao_critica()
        try:
            msg = json.dumps({"cmd": "NOVO_MEMBRO", "ip": self.meu_ip, "clock": self.lamport.get()}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            s.close()
        except Exception:
            print("[CONEXAO] Falha ao conectar ao coordenador")
        self.ricart.liberar_regiao_critica()
        try:
            msg = json.dumps({"cmd": "PEDIR_HASH", "ip": self.meu_ip}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            s.close()
        except Exception:
            print("[CONEXAO] Falha ao pedir hash ao coordenador")

    def _servidor_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PORTA_TCP))
        sock.listen(30)
        print(f"[TCP] Servidor escutando em {self.meu_ip}:{PORTA_TCP}")
        while not self.sair:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
            except Exception:
                continue

    def _handle_conn(self, conn, addr):
        try:
            data = conn.recv(4096)
            info = json.loads(data.decode())
            cmd = info.get("cmd")
            if cmd in ["REQUEST", "REPLY"]:
                self.ricart.receber_msg(info)
            elif cmd == "NOVO_MEMBRO":
                ip_novo = info.get("ip")
                self.ricart.pedir_regiao_critica()
                self.gerente.adicionar_maquina(ip_novo)
                self.gerente.replicar_lista(ip_novo)
                for ip in self.gerente.get_lista_maquinas():
                    if ip != self.meu_ip and ip != ip_novo:
                        try:
                            msg = json.dumps({"cmd": "NOVO_MEMBRO_PROPAGADO", "ip": ip_novo}).encode()
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(TIMEOUT)
                            s.connect((ip, PORTA_TCP))
                            s.sendall(msg)
                            s.close()
                        except Exception:
                            pass
                self.ricart.liberar_regiao_critica()
            elif cmd == "NOVO_MEMBRO_PROPAGADO":
                ip_novo = info.get("ip")
                self.ricart.pedir_regiao_critica()
                self.gerente.adicionar_maquina(ip_novo)
                self.ricart.liberar_regiao_critica()
            elif cmd == "LISTA_MAQUINAS":
                lista = info.get("lista", [])
                self.gerente.atualizar_lista(lista)
            elif cmd == "SENHA_ENCONTRADA":
                senha = info.get("senha")
                print(f"\n[SISTEMA] Senha encontrada por outro nó: {senha}")
                self.senha_encontrada = senha
                self.sair = True
            elif cmd == "PEDIR_HASH":
                if self.meu_ip == self.coordenador_ip:
                    try:
                        msg = json.dumps({"cmd": "CONFIG_HASH", "hash": self.alvo_md5}).encode()
                        conn.sendall(msg)
                    except Exception:
                        pass
            elif cmd == "CONFIG_HASH":
                self.alvo_md5 = info.get("hash")
                print(f"[SISTEMA] Hash alvo recebido do coordenador: {self.alvo_md5}")
        except Exception as e:
            print(f"[TCP] Erro ao tratar conexão: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _on_password_found(self, senha):
        print(f"\n[SISTEMA] Senha encontrada: {senha}")
        self.senha_encontrada = senha
        self.sair = True
        for ip in self.gerente.get_lista_maquinas():
            if ip != self.meu_ip:
                try:
                    msg = json.dumps({"cmd": "SENHA_ENCONTRADA", "senha": senha}).encode()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    s.connect((ip, PORTA_TCP))
                    s.sendall(msg)
                    s.close()
                except Exception:
                    pass

# ========== UTILITÁRIOS ==========
def get_meu_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def menu():
    print("="*60)
    print(" Brute Force MD5 Distribuído - IFBA Sistemas Distribuídos")
    print("="*60)
    print("1 - Iniciar como Coordenador")
    print("2 - Iniciar como Trabalhador")
    print("0 - Sair")
    return input("Escolha: ").strip()

def main():
    escolha = menu()
    if escolha == "1":
        meu_ip = get_meu_ip()
        print(f"Seu IP detectado: {meu_ip}")
        hash_md5 = input("Digite o hash MD5 alvo: ").strip()
        print("Iniciando como coordenador...")
        ServidorDistribuido(meu_ip, meu_ip, hash_md5)
        while True:
            time.sleep(1)
    elif escolha == "2":
        meu_ip = get_meu_ip()
        print(f"Seu IP detectado: {meu_ip}")
        coord_ip = input("Digite IP do coordenador: ").strip()
        print("Conectando ao coordenador para receber o hash alvo...")
        ServidorDistribuido(meu_ip, coord_ip, None)
        while True:
            time.sleep(1)
    elif escolha == "0":
        print("Saindo...")
        exit(0)
    else:
        print("Opção inválida.")
        main()

if __name__ == "__main__":
    main()