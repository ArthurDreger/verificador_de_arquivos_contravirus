import os
import time
import hashlib
import requests
import json
import csv
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
from datetime import datetime

# --- CONFIGURAÇÃO GLOBAL ---
ARQUIVO_HISTORICO = "vt_history_control.txt"
ARQUIVO_RELATORIO = "relatorio_scan.csv"
ARQUIVO_CONFIG = "config.json"

class VirusTotalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VirusTotal Pro Scanner")
        self.root.geometry("600x500")
        self.config = {}
        
        # Carrega configuração ao iniciar
        self.carregar_config()

        # --- INTERFACE ---
        # Frame do Topo (Botões)
        frame_top = tk.Frame(root, pady=10)
        frame_top.pack(fill=tk.X)

        tk.Label(frame_top, text="Selecione o alvo:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=10)
        
        self.btn_arq = tk.Button(frame_top, text="📄 Escanear Arquivo", command=self.scan_arquivo, bg="#dddddd")
        self.btn_arq.pack(side=tk.LEFT, padx=5)
        
        self.btn_pasta = tk.Button(frame_top, text="📁 Escanear Pasta", command=self.scan_pasta, bg="#dddddd")
        self.btn_pasta.pack(side=tk.LEFT, padx=5)

        # Barra de Progresso
        self.lbl_status = tk.Label(root, text="Aguardando...", anchor="w")
        self.lbl_status.pack(fill=tk.X, padx=10)
        
        self.progress = ttk.Progressbar(root, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=5)

        # Área de Log (Texto com rolagem)
        self.log_area = scrolledtext.ScrolledText(root, state='disabled', height=15)
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configurando cores para o texto
        self.log_area.tag_config("verde", foreground="green")
        self.log_area.tag_config("vermelho", foreground="red")
        self.log_area.tag_config("laranja", foreground="#ff8c00") # Dark Orange
        self.log_area.tag_config("azul", foreground="blue")

        # Verifica API Key
        if not self.config.get("api_key"):
            self.log("ERRO: Configure sua API KEY no arquivo config.json!", "vermelho")
            self.btn_arq['state'] = 'disabled'
            self.btn_pasta['state'] = 'disabled'

    def carregar_config(self):
        if os.path.exists(ARQUIVO_CONFIG):
            try:
                with open(ARQUIVO_CONFIG, "r") as f:
                    self.config = json.load(f)
            except:
                pass
        
        # Valores padrão se falhar
        if "limite_requisicoes" not in self.config: self.config["limite_requisicoes"] = 4
        if "intervalo_segundos" not in self.config: self.config["intervalo_segundos"] = 60

    def log(self, mensagem, tag=None):
        """Escreve na tela de log de forma segura"""
        self.log_area.config(state='normal') # Habilita edição
        self.log_area.insert(tk.END, f"{mensagem}\n", tag)
        self.log_area.see(tk.END) # Auto-scroll para o final
        self.log_area.config(state='disabled') # Trava edição

    # --- LÓGICA DE THREADING ---
    def scan_arquivo(self):
        path = filedialog.askopenfilename()
        if path:
            # Inicia uma Thread separada para não travar a janela
            threading.Thread(target=self.processar, args=([path],), daemon=True).start()

    def scan_pasta(self):
        path = filedialog.askdirectory()
        if path:
            arquivos = []
            for r, _, f in os.walk(path):
                for file in f: arquivos.append(os.path.join(r, file))
            
            threading.Thread(target=self.processar, args=(arquivos,), daemon=True).start()

    def processar(self, lista_arquivos):
        """Esta função roda em segundo plano (Worker Thread)"""
        total = len(lista_arquivos)
        self.log(f"--- Iniciando Scan de {total} arquivos ---", "azul")
        
        # Reseta Barra de Progresso
        self.progress['value'] = 0
        self.progress['maximum'] = total
        
        # Desabilita botões durante o processo
        self.btn_arq['state'] = 'disabled'
        self.btn_pasta['state'] = 'disabled'

        for i, caminho in enumerate(lista_arquivos):
            nome = os.path.basename(caminho)
            self.lbl_status['text'] = f"Analisando [{i+1}/{total}]: {nome}"
            self.log(f"Analisando: {nome}...", None)
            
            # 1. Calcula Hash
            h = self.calcular_hash(caminho)
            resultado = "ERRO"
            
            if h:
                # 2. Consulta API (com delay inteligente)
                resultado = self.consultar_api(h)
            
            # 3. Exibe e Salva
            cor = None
            if "LIMPO" in resultado: cor = "verde"
            elif "PERIGO" in resultado: cor = "vermelho"
            elif "SUSPEITO" in resultado: cor = "laranja"
            
            self.log(f"   --> Resultado: {resultado}", cor)
            self.salvar_csv(nome, h, resultado)
            
            # Atualiza barra
            self.progress['value'] = i + 1

        self.log("--- Processo Finalizado ---", "azul")
        self.lbl_status['text'] = "Pronto."
        self.btn_arq['state'] = 'normal'
        self.btn_pasta['state'] = 'normal'
        messagebox.showinfo("Fim", f"Verificação concluída.\nRelatório salvo em {ARQUIVO_RELATORIO}")

    # --- LÓGICA DE NEGÓCIO (CÓPIAS ADAPTADAS DO ANTERIOR) ---
    def gerenciar_limite(self):
        """Lógica do Delay Inteligente"""
        agora = time.time()
        timestamps = []
        if os.path.exists(ARQUIVO_HISTORICO):
            try:
                with open(ARQUIVO_HISTORICO, "r") as f:
                    for l in f: timestamps.append(float(l.strip()))
            except: pass
        
        limite_q = self.config["limite_requisicoes"]
        limite_t = self.config["intervalo_segundos"]
        recentes = [t for t in timestamps if (agora - t) < limite_t]

        if len(recentes) >= limite_q:
            wait = limite_t - (agora - min(recentes)) + 1
            if wait > 0:
                self.log(f"   [Limite API] Pausando por {wait:.1f}s...", "laranja")
                self.lbl_status['text'] = f"Pausa API ({wait:.0f}s)..."
                time.sleep(wait)
                agora = time.time()
                recentes = [t for t in recentes if (agora - t) < limite_t]
        
        recentes.append(agora)
        with open(ARQUIVO_HISTORICO, "w") as f:
            for t in recentes: f.write(f"{t}\n")

    def calcular_hash(self, path):
        s = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for b in iter(lambda: f.read(4096), b""): s.update(b)
            return s.hexdigest()
        except: return None

    def consultar_api(self, hash_arq):
        self.gerenciar_limite()
        url = f"https://www.virustotal.com/api/v3/files/{hash_arq}"
        headers = {"x-apikey": self.config.get("api_key")}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                m = r.json()['data']['attributes']['last_analysis_stats']['malicious']
                if m == 0: return "✅ LIMPO"
                elif m < 3: return f"⚠️ SUSPEITO ({m})"
                else: return f"🚨 PERIGO ({m})"
            elif r.status_code == 404: return "❓ DESCONHECIDO"
            else: return f"Erro API {r.status_code}"
        except Exception as e: return f"Erro Net: {e}"

    def salvar_csv(self, nome, hash_a, status):
        existe = os.path.exists(ARQUIVO_RELATORIO)
        try:
            with open(ARQUIVO_RELATORIO, "a", newline="", encoding="utf-8") as f:
                w = csv.writer(f, delimiter=";")
                if not existe: w.writerow(["DATA", "ARQUIVO", "STATUS", "HASH"])
                w.writerow([datetime.now().strftime("%d/%m %H:%M"), nome, status, hash_a])
        except: pass

if __name__ == "__main__":
    root = tk.Tk()
    app = VirusTotalApp(root)
    root.mainloop()