import os
import time
import hashlib
import requests
import tkinter as tk
from tkinter import filedialog, messagebox

# --- CONFIGURAÇÃO ---
API_KEY = "COLE_SUA_API_KEY_AQUI"
ARQUIVO_LOG = "vt_history.txt"  # Arquivo onde guardaremos os horários
LIMITE_REQUISICOES = 4
INTERVALO_SEGUNDOS = 60

def gerenciar_limite_api():
    """
    Lê o arquivo de log e garante que não excedemos 4 requests/minuto.
    Se necessário, pausa a execução pelo tempo exato.
    """
    agora = time.time()
    timestamps = []

    # 1. Lê o histórico existente
    if os.path.exists(ARQUIVO_LOG):
        try:
            with open(ARQUIVO_LOG, "r") as f:
                for linha in f:
                    try:
                        timestamps.append(float(linha.strip()))
                    except ValueError:
                        pass
        except Exception:
            pass

    # 2. Filtra: Mantém apenas os registros dos últimos 60 segundos
    timestamps_recentes = [t for t in timestamps if (agora - t) < INTERVALO_SEGUNDOS]

    # 3. Verifica se atingimos o limite
    if len(timestamps_recentes) >= LIMITE_REQUISICOES:
        # Pega o horário da requisição mais antiga desse grupo recente
        mais_antigo = min(timestamps_recentes)
        
        tempo_para_liberar = INTERVALO_SEGUNDOS - (agora - mais_antigo) + 1 # +1s de margem
        
        if tempo_para_liberar > 0:
            print(f" >> Limite atingido. Aguardando {tempo_para_liberar:.1f} segundos para evitar bloqueio...")
            time.sleep(tempo_para_liberar)
            # Atualiza o 'agora' pós-espera
            agora = time.time()
            # Recalcula a lista (remove o que expirou durante a espera)
            timestamps_recentes = [t for t in timestamps_recentes if (agora - t) < INTERVALO_SEGUNDOS]

    # 4. Adiciona o momento atual na lista e salva no arquivo
    timestamps_recentes.append(agora)
    
    with open(ARQUIVO_LOG, "w") as f:
        for t in timestamps_recentes:
            f.write(f"{t}\n")

def calcular_hash(caminho_arquivo):
    sha256 = hashlib.sha256()
    try:
        with open(caminho_arquivo, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                sha256.update(bloco)
        return sha256.hexdigest()
    except Exception as e:
        print(f" [X] Erro ao ler arquivo: {e}")
        return None

def consultar_virustotal(hash_arquivo):
    # CHAMA A FUNÇÃO DE DELAY INTELIGENTE ANTES DE CONSULTAR
    gerenciar_limite_api()
    
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            dados = response.json()
            stats = dados['data']['attributes']['last_analysis_stats']
            return stats['malicious']
        elif response.status_code == 404:
            return "Desconhecido (Nunca escaneado)"
        elif response.status_code == 429:
            return "ERRO: Limite de API excedido (O delay falhou?)"
        else:
            return f"Erro HTTP {response.status_code}"
    except Exception as e:
        return f"Erro Conexão: {e}"

def processar_alvo(caminho, eh_pasta):
    print(f"\n--- Iniciando Varredura ---")
    
    arquivos_para_processar = []

    if eh_pasta:
        for raiz, _, arquivos in os.walk(caminho):
            for arq in arquivos:
                arquivos_para_processar.append(os.path.join(raiz, arq))
    else:
        arquivos_para_processar.append(caminho)

    total = len(arquivos_para_processar)
    print(f"Alvo: {caminho}")
    print(f"Total de arquivos encontrados: {total}\n")

    for i, arquivo_path in enumerate(arquivos_para_processar):
        nome_arquivo = os.path.basename(arquivo_path)
        print(f"[{i+1}/{total}] Analisando: {nome_arquivo}...", end=" ", flush=True)

        file_hash = calcular_hash(arquivo_path)
        
        if file_hash:
            resultado = consultar_virustotal(file_hash)
            
            if isinstance(resultado, int):
                if resultado == 0:
                    print("✅ LIMPO")
                elif resultado < 3:
                    print(f"⚠️ SUSPEITO ({resultado} detecções)")
                else:
                    print(f"🚨 PERIGO! ({resultado} DETECÇÕES!)")
            else:
                print(f"❓ {resultado}")
        else:
            print("Pular (Erro leitura)")

    print("\n--- Processo Finalizado ---")
    input("Pressione ENTER para sair...")

# --- INTERFACE GRÁFICA (GUI) ---
def iniciar_gui():
    root = tk.Tk()
    root.title("Scanner VirusTotal")
    root.geometry("300x150")

    def selecionar_arquivo():
        path = filedialog.askopenfilename(title="Selecione um Arquivo")
        if path:
            root.destroy()
            processar_alvo(path, eh_pasta=False)

    def selecionar_pasta():
        path = filedialog.askdirectory(title="Selecione uma Pasta")
        if path:
            root.destroy()
            processar_alvo(path, eh_pasta=True)

    tk.Label(root, text="O que deseja verificar?", font=("Arial", 12)).pack(pady=10)
    
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=10)

    tk.Button(btn_frame, text="Arquivo Único", command=selecionar_arquivo, width=15).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="Pasta Inteira", command=selecionar_pasta, width=15).pack(side=tk.LEFT, padx=5)

    if API_KEY == "COLE_SUA_API_KEY_AQUI":
        messagebox.showerror("Erro", "Configure sua API KEY no código antes de usar!")
    else:
        root.mainloop()

if __name__ == "__main__":
    iniciar_gui()
