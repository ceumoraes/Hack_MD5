#!/usr/bin/env python3
"""
Força bruta distribuída de MD5 por comprimento

Modo coordenador ou trabalhador, escolha via menu interativo.
"""

import hashlib
import itertools
import socket
import threading
import time

CONJUNTOS = {
    "digitos": "0123456789",
    "minusculas": "abcdefghijklmnopqrstuvwxyz",
    "maiusculas": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "letras": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "minusculasdigitos": "abcdefghijklmnopqrstuvwxyz0123456789",
    "imprimiveis": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
}

def menu():
    print("="*50)
    print(" Força Bruta Distribuída de MD5")
    print("="*50)
    print("Selecione o modo de operação:")
    print("[1] Coordenador")
    print("[2] Trabalhador")
    print("[0] Sair")
    escolha = input("Digite o número da opção: ").strip()
    return escolha

def menu_coordenador():
    host = input("Host para escutar [0.0.0.0]: ").strip() or "0.0.0.0"
    porta = input("Porta para escutar [12001]: ").strip() or "12001"
    alvo = input("Hash MD5 alvo: ").strip()
    print("Conjuntos disponíveis:")
    for nome in CONJUNTOS:
        print(f"- {nome}")
    conjunto = input("Conjunto de caracteres [minusculasdigitos]: ").strip() or "minusculasdigitos"
    if conjunto in CONJUNTOS:
        conjunto = CONJUNTOS[conjunto]
    return host, int(porta), alvo, conjunto

def menu_trabalhador():
    servidor = input("IP/host do coordenador: ").strip()
    porta = input("Porta do coordenador [12001]: ").strip() or "12001"
    max_comprimento = input("Comprimento máximo [12]: ").strip() or "12"
    return servidor, int(porta), int(max_comprimento)

class Coordenador:
    def __init__(self, host, porta, alvo, conjunto):
        self.host = host
        self.porta = porta
        self.alvo = alvo
        self.conjunto = conjunto
        self.servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.servidor.bind((host, porta))
        self.servidor.listen(100)
        self.proximo_comprimento = 1
        self.designados = {}
        self.clientes = set()
        self.encontrado = False
        self.senha_encontrada = None
        self.lock = threading.Lock()

    def iniciar(self):
        print(f"[COORD] Escutando em {self.host}:{self.porta}")
        print(f"[COORD] Alvo MD5: {self.alvo}")
        print(f"[COORD] Conjunto: {self.conjunto}")
        threading.Thread(target=self._aceitar_conexoes, daemon=True).start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[COORD] Encerrando...")
            self._broadcast("PARAR\n")
            self._fechar_tudo()

    def _aceitar_conexoes(self):
        while True:
            conexao, endereco = self.servidor.accept()
            print(f"[COORD] Trabalhador conectado de {endereco[0]}:{endereco[1]}")
            with self.lock:
                self.clientes.add(conexao)
            self._enviar(conexao, f"CONFIG {self.alvo} {self.conjunto}\n")
            threading.Thread(target=self._tratar_cliente, args=(conexao,), daemon=True).start()

    def _tratar_cliente(self, conexao):
        try:
            conexao.settimeout(60)
            buf = b""
            while True:
                if self.encontrado:
                    if self.senha_encontrada:
                        self._enviar(conexao, f"PARAR ENCONTRADO {self.senha_encontrada}\n")
                    else:
                        self._enviar(conexao, "PARAR\n")
                    break
                dados = conexao.recv(4096)
                if not dados:
                    break
                buf += dados
                while b"\n" in buf:
                    linha, buf = buf.split(b"\n", 1)
                    self._tratar_linha(conexao, linha.decode(errors="ignore").strip())
        except Exception:
            pass
        finally:
            with self.lock:
                self.designados.pop(conexao, None)
                self.clientes.discard(conexao)
            try:
                conexao.close()
            except Exception:
                pass

    def _tratar_linha(self, conexao, linha):
        if not linha:
            return
        partes = linha.split()
        comando = partes[0].upper()
        if comando == "PEDIR":
            self._tratar_pedir(conexao)
        elif comando == "FINALIZADO" and len(partes) >= 2 and partes[1].isdigit():
            print(f"[COORD] FINALIZADO comprimento={partes[1]}")
            with self.lock:
                self.designados.pop(conexao, None)
        elif comando == "ENCONTRADO" and len(partes) >= 2:
            senha = linha[len("ENCONTRADO "):]
            print(f"[COORD] SENHA ENCONTRADA: '{senha}'")
            with self.lock:
                self.encontrado = True
                self.senha_encontrada = senha
            self._broadcast(f"PARAR ENCONTRADO {senha}\n")
        else:
            print(f"[COORD] Comando desconhecido: {linha}")

    def _tratar_pedir(self, conexao):
        with self.lock:
            if self.encontrado:
                msg = f"PARAR ENCONTRADO {self.senha_encontrada}\n" if self.senha_encontrada else "PARAR\n"
                self._enviar(conexao, msg)
                return
            comprimento = self.proximo_comprimento
            self.proximo_comprimento += 1
            self.designados[conexao] = comprimento
        print(f"[COORD] Designando comprimento={comprimento}")
        self._enviar(conexao, f"TAREFA {comprimento}\n")

    def _broadcast(self, msg):
        with self.lock:
            clientes = list(self.clientes)
        for c in clientes:
            try:
                c.sendall(msg.encode())
            except Exception:
                pass

    def _enviar(self, conexao, msg):
        try:
            conexao.sendall(msg.encode())
        except Exception:
            pass

    def _fechar_tudo(self):
        with self.lock:
            clientes = list(self.clientes)
        for c in clientes:
            try:
                c.close()
            except Exception:
                pass
        try:
            self.servidor.close()
        except Exception:
            pass

class Trabalhador:
    def __init__(self, servidor, porta, max_comprimento):
        self.servidor = servidor
        self.porta = porta
        self.max_comprimento = max_comprimento
        self.sock = None
        self.sair = False
        self.senha_encontrada = None
        self.alvo = None
        self.conjunto = None

    def iniciar(self):
        while not self.sair:
            try:
                self._conectar()
                self._configurar()
                self._executar()
            except KeyboardInterrupt:
                print("\n[TRAB] Interrompido")
                self.sair = True
            except Exception as e:
                print(f"[TRAB] Erro de conexão: {e}. Tentando novamente em 2s...")
                time.sleep(2)
        print("[TRAB] Finalizado")

    def _conectar(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(30)
        self.sock.connect((self.servidor, self.porta))
        print(f"[TRAB] Conectado a {self.servidor}:{self.porta}")

    def _enviar(self, msg):
        if self.sock:
            self.sock.sendall((msg + "\n").encode())

    def _receber_linha(self):
        if not self.sock:
            return None
        buf = b""
        while True:
            dados = self.sock.recv(4096)
            if not dados:
                return None
            buf += dados
            if b"\n" in buf:
                linha, _ = buf.split(b"\n", 1)
                return linha.decode(errors="ignore").strip()

    def _configurar(self):
        while True:
            linha = self._receber_linha()
            if linha is None:
                raise ConnectionError("Desconectado antes da configuração")
            partes = linha.split()
            if partes[0].upper() == "CONFIG" and len(partes) >= 3:
                self.alvo = partes[1].lower()
                self.conjunto = " ".join(partes[2:])
                print(f"[TRAB] Alvo recebido: {self.alvo}")
                print(f"[TRAB] Conjunto recebido: {self.conjunto}")
                break

    def _executar(self):
        while not self.sair:
            self._enviar("PEDIR")
            linha = self._receber_linha()
            if linha is None:
                print("[TRAB] Desconectado pelo coordenador")
                return
            partes = linha.split()
            comando = partes[0].upper()
            if comando == "TAREFA" and len(partes) >= 2:
                try:
                    comprimento = int(partes[1])
                except ValueError:
                    print(f"[TRAB] TAREFA inválida: {linha}")
                    continue
                print(f"[TRAB] Tarefa recebida comprimento={comprimento}")
                if comprimento > self.max_comprimento:
                    print(f"[TRAB] Comprimento {comprimento} acima do máximo. Parando.")
                    self.sair = True
                    return
                self._forca_bruta(comprimento)
                if self.sair:
                    return
                self._enviar(f"FINALIZADO {comprimento}")
            elif comando == "PARAR":
                if len(partes) >= 3 and partes[1].upper() == "ENCONTRADO":
                    self.senha_encontrada = " ".join(partes[2:])
                    print(f"[TRAB] PARAR - Senha encontrada: {self.senha_encontrada}")
                else:
                    print("[TRAB] PARAR recebido")
                self.sair = True
                return
            elif comando == "AGUARDE":
                time.sleep(0.5)
            else:
                print(f"[TRAB] Comando desconhecido do coordenador: {linha}")
                time.sleep(0.5)

    def _forca_bruta(self, comprimento):
        alvo = self.alvo
        conjunto = self.conjunto
        for tup in itertools.product(conjunto, repeat=comprimento):
            if self.sair:
                return
            s = ''.join(tup)
            h = hashlib.md5(s.encode()).hexdigest()
            if h == alvo:
                print(f"[TRAB] ENCONTRADO '{s}' para comprimento={comprimento}")
                self._enviar(f"ENCONTRADO {s}")
                self.sair = True
                self.senha_encontrada = s
                return

def main():
    while True:
        escolha = menu()
        if escolha == "1":
            host, porta, alvo, conjunto = menu_coordenador()
            Coordenador(host, porta, alvo, conjunto).iniciar()
            break
        elif escolha == "2":
            servidor, porta, max_comprimento = menu_trabalhador()
            Trabalhador(servidor, porta, max_comprimento).iniciar()
            break
        elif escolha == "0":
            print("Saindo...")
            break
        else:
            print("Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()