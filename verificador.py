import os
import time
import hashlib
import requests
import tkinter as tk
from tkinter import filedialog, messagebox

# --- CONFIGURAÇÃO ---
API_KEY = "COLE_SUA_API_KEY_AQUI"
ARQUIVO_LOG = "vt_history.txt"
LIMITE_REQUISICOES = 4
INTERVALO_SEGUNDOS = 60

def gerenciar_limite_api():
    """Gerencia o limite de 4 requisições por minuto"""
    agora = time.time()
    timestamps = []

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

    timestamps_recentes = [t for t in timestamps if (agora - t) < INTERVALO_SEGUNDOS]

    if len(timestamps_recentes) >= LIMITE_REQUISICOES:
        mais_antigo = min(timestamps_recentes)
        tempo_para_liberar = INTERVALO_SEGUNDOS - (agora - mais_antigo) + 1
        
        if tempo_para_liberar > 0:
            print(f" >> Limite de API próximo. Aguardando {tempo_para_liberar:.1f}s...")
            time.sleep(tempo_para_liberar)
            agora = time.time()
            timestamps_recentes = [t for t in timestamps_recentes if (agora - t) < INTERVALO_SEGUNDOS]

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

def consultar_hash(hash_arquivo):
    gerenciar_limite_api() # Conta como 1 requisição
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return None # Não encontrado
        else:
            return f"Erro {response.status_code}"
    except Exception as e:
        return f"Erro Conexão: {e}"

def fazer_upload(caminho_arquivo):
    """Envia o arquivo físico para o VirusTotal"""
    print(" >> Enviando arquivo (isso pode demorar dependendo do tamanho)...")
    gerenciar_limite_api() # Conta como 1 requisição
    
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}
    
    try:
        with open(caminho_arquivo, "rb") as f:
            files = {"file": (os.path.basename(caminho_arquivo), f)}
            response = requests.post(url, headers=headers, files=files)
        
        if response.status_code == 200:
            return response.json()['data']['id'] # Retorna o ID da análise
        else:
            print(f"Erro no upload: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Erro ao enviar: {e}")
        return None

def checar_analise(analysis_id):
    """Verifica se a análise do arquivo enviado já terminou"""
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    
    while True:
        gerenciar_limite_api() # Conta como 1 requisição a cada tentativa
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            dados = response.json()
            status = dados['data']['attributes']['status']
            
            if status == "completed":
                return dados['data']['attributes']['stats']['malicious']
            else:
                print(" >> Ainda analisando... aguardando 20 segundos...")
                time.sleep(20) # Espera manual para não gastar API à toa
        else:
            print(f"Erro ao checar status: {response.status_code}")
            return None

def exibir_resultado(malicioso):
    if isinstance(malicioso, int):
        if malicioso == 0:
            print("✅ LIMPO (Após análise profunda)")
        elif malicioso < 3:
            print(f"⚠️ SUSPEITO ({malicioso} detecções)")
        else:
            print(f"🚨 PERIGO! ({malicioso} DETECÇÕES!)")
    else:
        print(f"❓ Resultado inconclusivo: {malicioso}")

def processar_alvo(caminho, eh_pasta):
    arquivos = []
    if eh_pasta:
        for r, _, f in os.walk(caminho):
            for file in f: arquivos.append(os.path.join(r, file))
    else:
        arquivos.append(caminho)

    print(f"--- Iniciando --- Total: {len(arquivos)}")

    for i, arquivo_path in enumerate(arquivos):
        nome = os.path.basename(arquivo_path)
        print(f"[{i+1}/{len(arquivos)}] {nome}...", end=" ", flush=True)

        file_hash = calcular_hash(arquivo_path)
        if not file_hash: continue

        # 1. Tenta consultar pelo Hash
        resposta = consultar_hash(file_hash)

        if isinstance(resposta, dict):
            # Já existe no banco
            malicioso = resposta['data']['attributes']['last_analysis_stats']['malicious']
            if malicioso == 0: print("✅ LIMPO")
            elif malicioso < 3: print(f"⚠️ SUSPEITO ({malicioso})")
            else: print(f"🚨 PERIGO ({malicioso})")
        
        elif resposta is None:
            # Não existe
            print("❓ DESCONHECIDO.")
            escolha = input("    >> Arquivo nunca visto. Deseja fazer UPLOAD para verificar? (s/n): ").lower()
            
            if escolha == 's':
                analise_id = fazer_upload(arquivo_path)
                if analise_id:
                    print("    >> Aguardando resultado da análise na nuvem...")
                    resultado_upload = checar_analise(analise_id)
                    print(f"    >> Resultado final para {nome}: ", end="")
                    exibir_resultado(resultado_upload)
            else:
                print("    >> Pulado.")
        else:
            print(f"Erro: {resposta}")

    print("\n--- Fim ---")
    input("Enter para sair...")

# --- GUI ---
def iniciar_gui():
    root = tk.Tk()
    root.title("Scanner VirusTotal PRO")
    root.geometry("300x150")

    def sel_arq():
        p = filedialog.askopenfilename()
        if p: 
            root.destroy()
            processar_alvo(p, False)

    def sel_pasta():
        p = filedialog.askdirectory()
        if p: 
            root.destroy()
            processar_alvo(p, True)

    tk.Label(root, text="Scanner VirusTotal v2", font=("Arial", 12)).pack(pady=10)
    tk.Button(root, text="Arquivo", command=sel_arq).pack(side=tk.LEFT, padx=20)
    tk.Button(root, text="Pasta", command=sel_pasta).pack(side=tk.RIGHT, padx=20)
    
    if API_KEY == "COLE_SUA_API_KEY_AQUI":
        messagebox.showerror("Erro", "Configure a API KEY!")
    else:
        root.mainloop()

if __name__ == "__main__":
    iniciar_gui()
