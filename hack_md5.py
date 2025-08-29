import threading
import socket
import time
import hashlib
import itertools
import json
import random

PORTA_TCP = 12001
TIMEOUT = 30
CHECAGEM_COORDENADOR_INTERVALO = 5  # segundos

CONJUNTOS = [
    "digitos",
    "minusculas",
    "maiusculas",
    "letras",
    "minusculasdigitos",
    "imprimiveis"
]
CONJUNTOS_MAP = {
    "digitos": "0123456789",
    "minusculas": "abcdefghijklmnopqrstuvwxyz",
    "maiusculas": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "letras": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "minusculasdigitos": "abcdefghijklmnopqrstuvwxyz0123456789",
    "imprimiveis": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

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

class GerenteDistribuido:
    def __init__(self, meu_ip, is_coordenador):
        self.meu_ip = meu_ip
        self.is_coordenador = is_coordenador
        self.lista_maquinas = [meu_ip]
        self.tarefas = {}
        self.lock = threading.Lock()
        self.proximo_comprimento = 1
        self.proximo_conjunto = 0
        self.senha_encontrada = None

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

    def atribuir_tarefa(self, ip, conjuntos):
        with self.lock:
            if self.senha_encontrada is not None:
                return None, None
            tarefa = self.tarefas.get(ip)
            if tarefa is None or tarefa.get("status") == "finalizado":
                comprimento = self.proximo_comprimento
                conjunto_idx = self.proximo_conjunto
                conjunto_nome = conjuntos[conjunto_idx]
                self.tarefas[ip] = {
                    "comprimento": comprimento,
                    "conjunto": conjunto_nome,
                    "status": "em_andamento"
                }
                print(f"[DEBUG][COORD] Atribuindo tarefa para IP {ip}: comprimento={comprimento}, conjunto={conjunto_nome}")
                self.proximo_conjunto += 1
                if self.proximo_conjunto >= len(conjuntos):
                    self.proximo_conjunto = 0
                    self.proximo_comprimento += 1
                return comprimento, conjunto_nome
            else:
                return tarefa["comprimento"], tarefa["conjunto"]

    def finalizar_tarefa(self, ip):
        with self.lock:
            if ip in self.tarefas:
                self.tarefas[ip]["status"] = "finalizado"

    def registrar_tarefa_andamento(self, ip, comprimento, conjunto_nome):
        with self.lock:
            self.tarefas[ip] = {
                "comprimento": comprimento,
                "conjunto": conjunto_nome,
                "status": "em_andamento"
            }

    def get_lista_maquinas(self):
        with self.lock:
            return list(self.lista_maquinas)

    def get_tarefas(self):
        with self.lock:
            return dict(self.tarefas)

    def restaurar_progresso_tarefas(self):
        with self.lock:
            max_comprimento = 1
            max_conjunto_idx = 0
            for tarefa in self.tarefas.values():
                comprimento = tarefa["comprimento"]
                conjunto_nome = tarefa["conjunto"]
                conjunto_idx = CONJUNTOS.index(conjunto_nome)
                if comprimento > max_comprimento or (comprimento == max_comprimento and conjunto_idx > max_conjunto_idx):
                    max_comprimento = comprimento
                    max_conjunto_idx = conjunto_idx
            self.proximo_comprimento = max_comprimento
            self.proximo_conjunto = max_conjunto_idx + 1
            if self.proximo_conjunto >= len(CONJUNTOS):
                self.proximo_conjunto = 0
                self.proximo_comprimento += 1
            print(f"[COORD-ELEIÇÃO] Restaurando progresso de tarefas: próximo comprimento={self.proximo_comprimento}, próximo conjunto={self.proximo_conjunto}")

class BruteForceMD5(threading.Thread):
    def __init__(self, meu_ip, gerente, lamport, alvo_hash, conjuntos, coordenador_ip, on_trab_coord=None):
        super().__init__(daemon=True)
        self.meu_ip = meu_ip
        self.gerente = gerente
        self.lamport = lamport
        self.alvo_hash = alvo_hash
        self.conjuntos = conjuntos
        self.coordenador_ip = coordenador_ip
        self.sair = False
        self.on_trab_coord = on_trab_coord  # callback para promover a si mesmo a coordenador

    def pedir_tarefa_ao_coordenador(self):
        try:
            msg = json.dumps({"cmd": "PEDIR_TAREFA", "ip": self.meu_ip}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            resposta = s.recv(4096)
            s.close()
            if not resposta:
                return None, None
            info = json.loads(resposta.decode())
            if info.get("cmd") == "TAREFA_ASSIGNADA":
                comprimento = info["comprimento"]
                conjunto_nome = info["conjunto"]
                self.gerente.registrar_tarefa_andamento(self.meu_ip, comprimento, conjunto_nome)
                print(f"[DEBUG] Tarefa recebida: comprimento={comprimento}, conjunto={conjunto_nome}")
                return comprimento, conjunto_nome
            return None, None
        except Exception as e:
            print(f"[TRAB] Erro ao pedir tarefa ao coordenador: {e}")
        return None, None

    def notificar_finalizacao(self):
        try:
            msg = json.dumps({"cmd": "TAREFA_FINALIZADA", "ip": self.meu_ip}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            s.close()
        except Exception:
            pass

    def run(self):
        while self.alvo_hash is None:
            time.sleep(0.5)
        print(f"[DEBUG] Hash alvo recebido: {self.alvo_hash}")
        print(f"[DEBUG][TRAB] Lista de máquinas: {self.gerente.get_lista_maquinas()}")
        while not self.sair:
            if self.gerente.senha_encontrada is not None:
                break
            if self.meu_ip == self.coordenador_ip:
                print("[TRAB] Tornei-me coordenador, encerrando brute force trabalhador.")
                break
            comprimento, conjunto_nome = self.pedir_tarefa_ao_coordenador()
            # Checagem: se falhou pedir tarefa e está sozinho, promova-se (chame callback)
            if comprimento is None:
                lista_maquinas = self.gerente.get_lista_maquinas()
                if len(lista_maquinas) == 1 and lista_maquinas[0] == self.meu_ip and self.on_trab_coord is not None:
                    print("[TRAB] Detected I am the only one left, becoming coordinator!")
                    self.on_trab_coord()
                    self.sair = True
                    break
                print("[TRAB] Parando execução pois senha foi encontrada ou não há mais tarefas.")
                break
            print(f"[BF] Testando senhas de comprimento={comprimento}, conjunto={conjunto_nome}")
            conjunto = CONJUNTOS_MAP[conjunto_nome]
            achou = self._forca_bruta(comprimento, conjunto)
            self.gerente.finalizar_tarefa(self.meu_ip)
            if achou:
                self._on_password_found(achou)
                break
            self.notificar_finalizacao()

    def _forca_bruta(self, comprimento, conjunto):
        alvo = self.alvo_hash.lower()
        print(f"[DEBUG] [BF] Comprimento: {comprimento}, conjunto: {conjunto}")
        for tup in itertools.product(conjunto, repeat=comprimento):
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            print(f"[DEBUG] Testando: {s} -> {h}")
            if h == alvo:
                print(f"\n[BF] SENHA ENCONTRADA: '{s}' para comprimento={comprimento} e conjunto {conjunto}")
                return s
        print("\033[2K\r", end="")
        return None

    def _on_password_found(self, senha):
        print(f"[TRAB] Senha encontrada: {senha}")
        for ip in self.gerente.get_lista_maquinas():
            if ip != self.meu_ip:
                try:
                    msg = json.dumps({"cmd": "SENHA_ENCONTRADA", "senha": senha}).encode()
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(TIMEOUT)
                    s.connect((ip, PORTA_TCP))
                    s.sendall(msg)
                    s.close()
                except Exception as e:
                    print(f"[TRAB] Falha ao enviar SENHA_ENCONTRADA para {ip}: {e}")
        self.gerente.senha_encontrada = senha
        self.sair = True

class ServidorDistribuido:
    def __init__(self, meu_ip, coordenador_ip, alvo_md5):
        self.meu_ip = meu_ip
        self.coordenador_ip = coordenador_ip
        self.alvo_md5 = alvo_md5
        self.lamport = LamportClock()
        self.is_coordenador = (self.meu_ip == self.coordenador_ip)
        self.gerente = GerenteDistribuido(meu_ip, self.is_coordenador)
        self.senha_encontrada = None
        self.sair = False
        self.brute_force = None

        threading.Thread(target=self._servidor_tcp, daemon=True).start()
        threading.Thread(target=self._verificar_coordenador_periodicamente, daemon=True).start()

        if not self.is_coordenador:
            self.conectar_ao_sistema()
            wait_count = 0
            while self.alvo_md5 is None:
                time.sleep(0.5)
                wait_count += 1
                if wait_count % 10 == 0:
                    print("Trabalhador aguardando recebimento do hash...")
            print(f"Trabalhador vai iniciar brute force com hash: {self.alvo_md5}")
            self.iniciar_brute_force_trabalhador()

        print(f"Inicializando ServidorDistribuido ({'COORDENADOR' if self.is_coordenador else 'TRABALHADOR'})")
        print(f"meu_ip={self.meu_ip}, coordenador_ip={self.coordenador_ip}, alvo_md5={self.alvo_md5}")

    def iniciar_brute_force_trabalhador(self):
        self.brute_force = BruteForceMD5(
            meu_ip=self.meu_ip,
            gerente=self.gerente,
            lamport=self.lamport,
            alvo_hash=self.alvo_md5,
            conjuntos=CONJUNTOS,
            coordenador_ip=self.coordenador_ip,
            on_trab_coord=self.promover_a_coordenador
        )
        self.brute_force.start()

    def promover_a_coordenador(self):
        # Usa a mesma lógica de eleição da thread de verificação
        print("[PROMOÇÃO] Promovendo-me a coordenador por detecção no trabalhador...")
        self._iniciar_eleicao()

    def conectar_ao_sistema(self):
        print("Solicitando entrada no sistema...")
        try:
            msg = json.dumps({"cmd": "NOVO_MEMBRO", "ip": self.meu_ip}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            s.close()
        except Exception as e:
            print(f"Falha ao conectar ao coordenador: {e}")
        try:
            msg = json.dumps({"cmd": "PEDIR_HASH", "ip": self.meu_ip}).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(TIMEOUT)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.sendall(msg)
            resposta = s.recv(4096)
            info = json.loads(resposta.decode())
            if info.get("cmd") == "CONFIG_HASH":
                self.alvo_md5 = info.get("hash")
                print(f"Hash alvo recebido do coordenador: {self.alvo_md5}")
            s.close()
        except Exception as e:
            print(f"Falha ao pedir hash ao coordenador: {e}")

    def _verificar_coordenador_periodicamente(self):
        while not self.sair and self.gerente.senha_encontrada is None:
            time.sleep(CHECAGEM_COORDENADOR_INTERVALO)
            if self.sair or self.gerente.senha_encontrada is not None:
                break
            lista = self.gerente.get_lista_maquinas()
            if len(lista) == 1 and lista[0] == self.meu_ip and not self.is_coordenador:
                print("[ELEIÇÃO] Só eu restando, assumindo como coordenador!")
                self._iniciar_eleicao()
            elif not self._checar_coordenador():
                print("[ELEIÇÃO] Coordenador indisponível! Iniciando eleição...")
                self._iniciar_eleicao()

    def _checar_coordenador(self):
        if self.coordenador_ip == self.meu_ip:
            return True
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.coordenador_ip, PORTA_TCP))
            s.close()
            return True
        except Exception:
            return False

    def _iniciar_eleicao(self):
        lista = self.gerente.get_lista_maquinas()
        if self.coordenador_ip in lista and self.coordenador_ip != self.meu_ip:
            self.gerente.remover_maquina(self.coordenador_ip)
            lista = self.gerente.get_lista_maquinas()
        if not lista:
            print("[ELEIÇÃO] Nenhuma máquina disponível para ser coordenador.")
            return
        novo_coord = lista[0]
        if novo_coord == self.meu_ip:
            print("[ELEIÇÃO] Eu sou o novo coordenador!")
            self.is_coordenador = True
            self.coordenador_ip = self.meu_ip
            self.gerente.restaurar_progresso_tarefas()
            for ip in lista:
                if ip != self.meu_ip:
                    try:
                        msg = json.dumps({"cmd": "NOVO_COORDENADOR", "ip": self.meu_ip}).encode()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((ip, PORTA_TCP))
                        s.sendall(msg)
                        s.close()
                    except Exception as e:
                        print(f"[ELEIÇÃO] Falha ao notificar {ip}: {e}")
            if self.brute_force:
                self.brute_force.sair = True
                self.brute_force = None
        else:
            self.is_coordenador = False
            self.coordenador_ip = novo_coord
            print(f"[ELEIÇÃO] Novo coordenador é {novo_coord}")
            if self.brute_force:
                self.brute_force.coordenador_ip = self.coordenador_ip

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
            if not data:
                return
            info = json.loads(data.decode())
            cmd = info.get("cmd")
            if cmd == "NOVO_MEMBRO":
                ip_novo = info.get("ip")
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
            elif cmd == "NOVO_MEMBRO_PROPAGADO":
                ip_novo = info.get("ip")
                self.gerente.adicionar_maquina(ip_novo)
            elif cmd == "LISTA_MAQUINAS":
                lista = info.get("lista", [])
                self.gerente.atualizar_lista(lista)
            elif cmd == "SENHA_ENCONTRADA":
                senha = info.get("senha")
                print(f"Senha encontrada: {senha}")
                print("[TRAB] Senha encontrada, encerrando brute force.")
                self.senha_encontrada = senha
                self.sair = True
                self.gerente.senha_encontrada = senha
            elif cmd == "PEDIR_HASH":
                if self.is_coordenador:
                    try:
                        msg = json.dumps({"cmd": "CONFIG_HASH", "hash": self.alvo_md5}).encode()
                        conn.sendall(msg)
                    except Exception:
                        pass
            elif cmd == "CONFIG_HASH":
                self.alvo_md5 = info.get("hash")
                print(f"Hash alvo recebido do coordenador: {self.alvo_md5}")
            elif cmd == "PEDIR_TAREFA":
                if self.is_coordenador:
                    ip_trab = info.get("ip")
                    comprimento, conjunto_nome = self.gerente.atribuir_tarefa(ip_trab, CONJUNTOS)
                    if comprimento is None:
                        msg = json.dumps({
                            "cmd": "TAREFA_ASSIGNADA",
                            "comprimento": None,
                            "conjunto": None
                        }).encode()
                    else:
                        msg = json.dumps({
                            "cmd": "TAREFA_ASSIGNADA",
                            "comprimento": comprimento,
                            "conjunto": conjunto_nome
                        }).encode()
                    conn.sendall(msg)
            elif cmd == "TAREFA_FINALIZADA":
                if self.is_coordenador:
                    ip_trab = info.get("ip")
                    self.gerente.finalizar_tarefa(ip_trab)
            elif cmd == "NOVO_COORDENADOR":
                novo_coord_ip = info.get("ip")
                print(f"[ELEIÇÃO] Recebido NOVO_COORDENADOR: {novo_coord_ip}")
                self.coordenador_ip = novo_coord_ip
                self.is_coordenador = (self.meu_ip == self.coordenador_ip)
                if self.is_coordenador:
                    self.gerente.restaurar_progresso_tarefas()
                    if self.brute_force:
                        self.brute_force.sair = True
                        self.brute_force = None
                else:
                    if self.brute_force:
                        self.brute_force.coordenador_ip = self.coordenador_ip
        except Exception as e:
            print(f"Erro ao tratar conexão: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

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
        servidor = ServidorDistribuido(meu_ip, meu_ip, hash_md5)
        while True:
            if servidor.senha_encontrada is not None:
                print(f"\n[SOLUÇÃO FINAL] Senha encontrada: {servidor.senha_encontrada}")
                break
            time.sleep(1)
    elif escolha == "2":
        meu_ip = get_meu_ip()
        print(f"Seu IP detectado: {meu_ip}")
        coord_ip = input("Digite IP do coordenador: ").strip()
        print("Conectando ao coordenador para receber o hash alvo...")
        servidor = ServidorDistribuido(meu_ip, coord_ip, None)
        while servidor.gerente.senha_encontrada is None:
            time.sleep(1)
        exit(0)
    elif escolha == "0":
        print("Saindo...")
        exit(0)
    else:
        print("Opção inválida.")
        main()

if __name__ == "__main__":
    main()