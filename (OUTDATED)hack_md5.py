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
    "minusculasdigitos": "abcdefghijklmnopqrstuvwxyz0123456789",
    "imprimiveis": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}
CONJUNTOS = list(CONJUNTOS_MAP.keys())

def debug(clock, msg):
    print(f"[DEBUG][{clock.get()}] {msg}")

def mostrar_combinacoes_testadas(clock, comprimento, conjunto_nome, tentativa, hash_tentativa):
    print(f"[{clock.get()}] Testando combinação: '{tentativa}' (comprimento={comprimento}, conjunto={conjunto_nome}) -> Hash: {hash_tentativa}")

class RelogioBerkeley:
    def __init__(self):
        self.tempo = time.time() + random.randint(-30, 30)

    def tick(self, inc=1):
        self.tempo += inc
        return self.tempo

    def set(self, novo_tempo):
        self.tempo = novo_tempo
        return self.tempo

    def get(self):
        return float(f"{self.tempo:.2f}")

class GerenteDistribuido:
    def __init__(self, meu_ip, is_coordenador, clock):
        self.meu_ip = meu_ip
        self.is_coordenador = is_coordenador
        self.clock = clock
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
                debug(self.clock, f"[MAQUINAS] Máquina adicionada {ip}")

    def remover_maquina(self, ip):
        with self.lock:
            if ip in self.lista_maquinas:
                self.lista_maquinas.remove(ip)
                debug(self.clock, f"[MAQUINAS] Máquina removida {ip}")
            self.tarefas.pop(ip, None)

    def replicar_lista(self, destino_ip):
        msg = json.dumps({"cmd": "LISTA_MAQUINAS", "lista": self.lista_maquinas}).encode()
        try:
            with socket.create_connection((destino_ip, PORTA_TCP), TIMEOUT) as s:
                s.sendall(msg)
        except:
            pass

    def atualizar_lista(self, nova_lista):
        with self.lock:
            self.lista_maquinas = list(nova_lista)
            debug(self.clock, f"[MAQUINAS] Lista atualizada: {self.lista_maquinas}")

    def atribuir_tarefa(self, ip, conjuntos):
        with self.lock:
            if self.senha_encontrada is not None:
                return None, None
            tarefa = self.tarefas.get(ip)
            if not tarefa or tarefa.get("status") == "finalizado":
                comprimento = self.proximo_comprimento
                conjunto_idx = self.proximo_conjunto
                conjunto_nome = conjuntos[conjunto_idx]
                self.tarefas[ip] = {
                    "comprimento": comprimento,
                    "conjunto": conjunto_nome,
                    "status": "em_andamento"
                }
                debug(self.clock, f"[COORD] Atribuindo tarefa para {ip}: comprimento={comprimento}, conjunto={conjunto_nome}")
                self.proximo_conjunto += 1
                if self.proximo_conjunto >= len(conjuntos):
                    self.proximo_conjunto = 0
                    self.proximo_comprimento += 1
                return comprimento, conjunto_nome
            return tarefa["comprimento"], tarefa["conjunto"]

    def finalizar_tarefa(self, ip):
        with self.lock:
            if ip in self.tarefas:
                self.tarefas[ip]["status"] = "finalizado"
                debug(self.clock, f"[COORD] Tarefa finalizada para {ip}")

    def registrar_tarefa_andamento(self, ip, comprimento, conjunto_nome):
        with self.lock:
            self.tarefas[ip] = {
                "comprimento": comprimento,
                "conjunto": conjunto_nome,
                "status": "em_andamento"
            }
            debug(self.clock, f"Registrando tarefa em andamento para {ip}: comprimento={comprimento}, conjunto={conjunto_nome}")

    def get_lista_maquinas(self):
        with self.lock:
            return list(self.lista_maquinas)

    def restaurar_progresso_tarefas(self):
        with self.lock:
            max_comprimento, max_conjunto_idx = 1, 0
            for tarefa in self.tarefas.values():
                comprimento = tarefa["comprimento"]
                conjunto_idx = CONJUNTOS.index(tarefa["conjunto"])
                if comprimento > max_comprimento or (comprimento == max_comprimento and conjunto_idx > max_conjunto_idx):
                    max_comprimento, max_conjunto_idx = comprimento, conjunto_idx
            self.proximo_comprimento = max_comprimento
            self.proximo_conjunto = max_conjunto_idx + 1
            if self.proximo_conjunto >= len(CONJUNTOS):
                self.proximo_conjunto = 0
                self.proximo_comprimento += 1
            debug(self.clock, f"[COORD-ELEIÇÃO] Restaurando progresso das tarefas: próximo comprimento={self.proximo_comprimento}, próximo conjunto={self.proximo_conjunto}")

class ForcaBrutaMD5(threading.Thread):
    def __init__(self, meu_ip, gerente, clock, alvo_hash, conjuntos, coordenador_ip, on_trab_coord=None):
        super().__init__(daemon=True)
        self.meu_ip = meu_ip
        self.gerente = gerente
        self.clock = clock
        self.alvo_hash = alvo_hash
        self.conjuntos = conjuntos
        self.coordenador_ip = coordenador_ip
        self.sair = False
        self.on_trab_coord = on_trab_coord

    def pedir_tarefa_ao_coordenador(self):
        msg = json.dumps({"cmd": "PEDIR_TAREFA", "ip": self.meu_ip}).encode()
        try:
            with socket.create_connection((self.coordenador_ip, PORTA_TCP), TIMEOUT) as s:
                s.sendall(msg)
                resposta = s.recv(4096)
                if resposta:
                    info = json.loads(resposta.decode())
                    if info.get("cmd") == "TAREFA_ASSIGNADA":
                        comprimento, conjunto_nome = info["comprimento"], info["conjunto"]
                        self.gerente.registrar_tarefa_andamento(self.meu_ip, comprimento, conjunto_nome)
                        debug(self.clock, f"Tarefa recebida: comprimento={comprimento}, conjunto={conjunto_nome}")
                        return comprimento, conjunto_nome
        except Exception as e:
            debug(self.clock, f"[TRAB] Erro ao pedir tarefa ao coordenador: {e}")
        return None, None

    def notificar_finalizacao(self):
        msg = json.dumps({"cmd": "TAREFA_FINALIZADA", "ip": self.meu_ip}).encode()
        try:
            with socket.create_connection((self.coordenador_ip, PORTA_TCP), TIMEOUT) as s:
                s.sendall(msg)
        except:
            pass

    def run(self):
        while self.alvo_hash is None:
            time.sleep(0.5)
        debug(self.clock, f"Hash alvo recebido: {self.alvo_hash}")
        debug(self.clock, f"[TRAB] Lista de máquinas: {self.gerente.get_lista_maquinas()}")
        while not self.sair and self.gerente.senha_encontrada is None:
            if self.meu_ip == self.coordenador_ip:
                debug(self.clock, "[TRAB] Tornei-me coordenador, encerrando operação de força bruta.")
                break
            comprimento, conjunto_nome = self.pedir_tarefa_ao_coordenador()
            if comprimento is None:
                if len(self.gerente.get_lista_maquinas()) == 1 and self.on_trab_coord:
                    debug(self.clock, "[TRAB] Detectei que sou o único, tornando-me coordenador!")
                    self.on_trab_coord()
                break
            debug(self.clock, f"[FB] Testando senhas de comprimento={comprimento}, conjunto={conjunto_nome}")
            conjunto = CONJUNTOS_MAP[conjunto_nome]
            achou = self._forca_bruta(comprimento, conjunto, conjunto_nome)
            self.gerente.finalizar_tarefa(self.meu_ip)
            if achou:
                self._on_password_found(achou)
                break
            self.notificar_finalizacao()

    def _forca_bruta(self, comprimento, conjunto, conjunto_nome):
        alvo = self.alvo_hash.lower()
        for tup in itertools.product(conjunto, repeat=comprimento):
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            mostrar_combinacoes_testadas(self.clock, comprimento, conjunto_nome, s, h)
            if h == alvo:
                debug(self.clock, f"[FB] SENHA ENCONTRADA: '{s}' para comprimento={comprimento} e conjunto {conjunto}")
                return s
        return None

    def _on_password_found(self, senha):
        debug(self.clock, f"[TRAB] Senha encontrada: {senha}")
        for ip in self.gerente.get_lista_maquinas():
            if ip != self.meu_ip:
                msg = json.dumps({"cmd": "SENHA_ENCONTRADA", "senha": senha}).encode()
                try:
                    with socket.create_connection((ip, PORTA_TCP), TIMEOUT) as s:
                        s.sendall(msg)
                except Exception as e:
                    debug(self.clock, f"[TRAB] Falha ao enviar SENHA_ENCONTRADA para {ip}: {e}")
        self.gerente.senha_encontrada = senha
        self.sair = True

class ServidorDistribuido:
    def __init__(self, meu_ip, coordenador_ip, alvo_md5):
        self.meu_ip = meu_ip
        self.coordenador_ip = coordenador_ip
        self.alvo_md5 = alvo_md5
        self.clock = RelogioBerkeley()
        self.is_coordenador = (self.meu_ip == self.coordenador_ip)
        self.gerente = GerenteDistribuido(meu_ip, self.is_coordenador, self.clock)
        self.senha_encontrada = None
        self.sair = False
        self.brute_force = None

        threading.Thread(target=self._servidor_tcp, daemon=True).start()
        threading.Thread(target=self._verificar_coordenador_periodicamente, daemon=True).start()
        threading.Thread(target=self._servidor_udp_berkeley, daemon=True).start()
        if self.is_coordenador:
            threading.Thread(target=self._sincronizar_berkeley_periodicamente, daemon=True).start()

        if not self.is_coordenador:
            self.conectar_ao_sistema()
            while self.alvo_md5 is None:
                time.sleep(0.5)
            self.iniciar_brute_force_trabalhador()

        debug(self.clock, f"Inicializando ServidorDistribuido ({'COORDENADOR' if self.is_coordenador else 'TRABALHADOR'})")
        print(f"meu_ip={self.meu_ip}, coordenador_ip={self.coordenador_ip}, alvo_md5={self.alvo_md5}")

    def iniciar_brute_force_trabalhador(self):
        self.brute_force = ForcaBrutaMD5(
            meu_ip=self.meu_ip,
            gerente=self.gerente,
            clock=self.clock,
            alvo_hash=self.alvo_md5,
            conjuntos=CONJUNTOS,
            coordenador_ip=self.coordenador_ip,
            on_trab_coord=self.promover_a_coordenador
        )
        self.brute_force.start()

    def promover_a_coordenador(self):
        debug(self.clock, "[PROMOÇÃO] Promovendo-me a coordenador por detecção no trabalhador...")
        self._iniciar_eleicao()

    def anunciar_novo_coordenador(self):
        debug(self.clock, "Anunciando para todas as máquinas que sou o novo coordenador!")
        msg = json.dumps({"cmd": "NOVO_COORDENADOR", "ip": self.meu_ip}).encode()
        for ip in self.gerente.get_lista_maquinas():
            if ip != self.meu_ip:
                try:
                    with socket.create_connection((ip, PORTA_TCP), 5) as s:
                        s.sendall(msg)
                except Exception as e:
                    debug(self.clock, f"Falha ao notificar {ip}: {e}")

    def conectar_ao_sistema(self):
        debug(self.clock, "Solicitando entrada no sistema...")
        msg_membro = json.dumps({"cmd": "NOVO_MEMBRO", "ip": self.meu_ip}).encode()
        msg_hash = json.dumps({"cmd": "PEDIR_HASH", "ip": self.meu_ip}).encode()
        try:
            with socket.create_connection((self.coordenador_ip, PORTA_TCP), TIMEOUT) as s:
                s.sendall(msg_membro)
        except Exception as e:
            debug(self.clock, f"Falha ao conectar ao coordenador: {e}")
        try:
            with socket.create_connection((self.coordenador_ip, PORTA_TCP), TIMEOUT) as s:
                s.sendall(msg_hash)
                resposta = s.recv(4096)
                info = json.loads(resposta.decode())
                if info.get("cmd") == "CONFIG_HASH":
                    self.alvo_md5 = info.get("hash")
                    debug(self.clock, f"Hash alvo recebido do coordenador: {self.alvo_md5}")
        except Exception as e:
            debug(self.clock, f"Falha ao pedir hash ao coordenador: {e}")

    def _verificar_coordenador_periodicamente(self):
        while not self.sair and self.gerente.senha_encontrada is None:
            time.sleep(CHECAGEM_COORDENADOR_INTERVALO)
            if self.sair or self.gerente.senha_encontrada is not None:
                break
            lista = self.gerente.get_lista_maquinas()
            if len(lista) == 1 and lista[0] == self.meu_ip and not self.is_coordenador:
                debug(self.clock, "[ELEIÇÃO] Só eu restando, assumindo como coordenador!")
                self.is_coordenador = True
                self.coordenador_ip = self.meu_ip
                self.gerente.restaurar_progresso_tarefas()
                self.anunciar_novo_coordenador()
            elif not self._checar_coordenador():
                debug(self.clock, "[ELEIÇÃO] Coordenador indisponível! Iniciando eleição...")
                self._iniciar_eleicao()

    def _checar_coordenador(self):
        if self.coordenador_ip == self.meu_ip:
            return True
        try:
            with socket.create_connection((self.coordenador_ip, PORTA_TCP), 3):
                return True
        except:
            return False

    def _iniciar_eleicao(self):
        lista = self.gerente.get_lista_maquinas()
        if self.coordenador_ip in lista and self.coordenador_ip != self.meu_ip:
            self.gerente.remover_maquina(self.coordenador_ip)
            lista = self.gerente.get_lista_maquinas()
        if not lista:
            debug(self.clock, "[ELEIÇÃO] Nenhuma máquina disponível para ser coordenador.")
            return
        novo_coord = lista[0]
        if novo_coord == self.meu_ip:
            debug(self.clock, "[ELEIÇÃO] Eu sou o novo coordenador!")
            self.is_coordenador = True
            self.coordenador_ip = self.meu_ip
            self.gerente.restaurar_progresso_tarefas()
            self.anunciar_novo_coordenador()
            if self.brute_force:
                self.brute_force.sair = True
                self.brute_force = None
        else:
            self.is_coordenador = False
            self.coordenador_ip = novo_coord
            debug(self.clock, f"[ELEIÇÃO] Novo coordenador é {novo_coord}")
            if self.brute_force:
                self.brute_force.coordenador_ip = self.coordenador_ip

    def _sincronizar_berkeley_periodicamente(self):
        while not self.sair:
            time.sleep(SINC_BERKLEY_INTERVALO)
            lista = self.gerente.get_lista_maquinas()
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
                for ip in lista:
                    delta = media - tempos[ip]
                    if ip == self.meu_ip:
                        self.clock.set(media)
                        debug(self.clock, f"[BERKELEY] Relógio ajustado para média {media:.2f}")
                    else:
                        try:
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                                s.sendto(f"{delta}".encode(), (ip, PORTA_UDP_BERKLEY))
                        except: pass

    def _servidor_udp_berkeley(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', PORTA_UDP_BERKLEY))
        while not self.sair:
            try:
                data, addr = sock.recvfrom(1024)
                msg = data.decode()
                if msg == "GET_TIME":
                    sock.sendto(str(self.clock.get()).encode(), addr)
                else:
                    try:
                        delta = float(msg)
                        self.clock.set(self.clock.get() + delta)
                        debug(self.clock, f"[BERKELEY] Relógio ajustado por delta {delta:.2f}")
                    except: pass
            except: continue

    def _servidor_tcp(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PORTA_TCP))
        sock.listen(30)
        debug(self.clock, f"[TCP] Servidor escutando em {self.meu_ip}:{PORTA_TCP}")
        while not self.sair:
            try:
                conn, addr = sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except: continue

    def _handle_conn(self, conn):
        try:
            data = conn.recv(4096)
            if not data:
                return
            info = json.loads(data.decode())
            cmd = info.get("cmd")
            ip_novo = info.get("ip")
            if cmd in ["NOVO_MEMBRO", "NOVO_MEMBRO_PROPAGADO"]:
                self.gerente.adicionar_maquina(ip_novo)
                if cmd == "NOVO_MEMBRO":
                    self.gerente.replicar_lista(ip_novo)
                    msg = json.dumps({"cmd": "NOVO_MEMBRO_PROPAGADO", "ip": ip_novo}).encode()
                    for ip in self.gerente.get_lista_maquinas():
                        if ip != self.meu_ip and ip != ip_novo:
                            try:
                                with socket.create_connection((ip, PORTA_TCP), TIMEOUT) as s:
                                    s.sendall(msg)
                            except: pass
            elif cmd == "LISTA_MAQUINAS":
                self.gerente.atualizar_lista(info.get("lista", []))
            elif cmd == "SENHA_ENCONTRADA":
                senha = info.get("senha")
                debug(self.clock, f"Senha encontrada: {senha}")
                print("[TRAB] Senha encontrada, encerrando força bruta.")
                self.senha_encontrada = senha
                self.sair = True
                self.gerente.senha_encontrada = senha
            elif cmd == "PEDIR_HASH":
                if self.is_coordenador:
                    msg = json.dumps({"cmd": "CONFIG_HASH", "hash": self.alvo_md5}).encode()
                    conn.sendall(msg)
            elif cmd == "CONFIG_HASH":
                self.alvo_md5 = info.get("hash")
                debug(self.clock, f"Hash alvo recebido do coordenador: {self.alvo_md5}")
            elif cmd == "PEDIR_TAREFA" and self.is_coordenador:
                ip_trab = info.get("ip")
                comprimento, conjunto_nome = self.gerente.atribuir_tarefa(ip_trab, CONJUNTOS)
                msg = json.dumps({
                    "cmd": "TAREFA_ASSIGNADA",
                    "comprimento": comprimento,
                    "conjunto": conjunto_nome
                }).encode()
                conn.sendall(msg)
            elif cmd == "TAREFA_FINALIZADA" and self.is_coordenador:
                self.gerente.finalizar_tarefa(info.get("ip"))
            elif cmd == "NOVO_COORDENADOR":
                novo_coord_ip = info.get("ip")
                debug(self.clock, f"[ELEIÇÃO] Recebido NOVO_COORDENADOR: {novo_coord_ip}")
                self.coordenador_ip = novo_coord_ip
                self.is_coordenador = (self.meu_ip == self.coordenador_ip)
                if self.is_coordenador:
                    self.gerente.restaurar_progresso_tarefas()
                    self.anunciar_novo_coordenador()
                    if self.brute_force:
                        self.brute_force.sair = True
                        self.brute_force = None
                elif self.brute_force:
                    self.brute_force.coordenador_ip = self.coordenador_ip
        except Exception as e:
            debug(self.clock, f"Erro ao tratar conexão: {e}")
        finally:
            try:
                conn.close()
            except: pass

def get_meu_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except:
        return "127.0.0.1"

def menu():
    print("="*60)
    print(" Força Bruta MD5 Distribuída")
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
        while servidor.senha_encontrada is None:
            time.sleep(1)
        print(f"\n[SOLUÇÃO FINAL] Senha encontrada: {servidor.senha_encontrada}")
    elif escolha == "2":
        meu_ip = get_meu_ip()
        print(f"Seu IP detectado: {meu_ip}")
        coord_ip = input("Digite o IP do coordenador: ").strip()
        print("Conectando ao coordenador para receber o hash alvo...")
        servidor = ServidorDistribuido(meu_ip, coord_ip, None)
        while servidor.gerente.senha_encontrada is None:
            time.sleep(1)
    elif escolha == "0":
        print("Saindo...")
    else:
        print("Opção inválida.")
        main()

if __name__ == "__main__":
    main()
