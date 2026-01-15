# -*- coding: utf-8 -*-
"""
Created on Thu Jan 15 13:38:58 2026

@author: arthu
"""

import os
import time
import hashlib
import requests
import tkinter as tk
from tkinter import filedialog

# --- CONFIGURAÇÃO ---
# Cole sua API Key do VirusTotal aqui
API_KEY = "COLE_SUA_API_KEY_AQUI"

def selecionar_pasta():
    """Abre uma janela nativa do sistema para escolher a pasta"""
    root = tk.Tk()
    root.withdraw() # Esconde a janelinha principal do Tkinter
    pasta_selecionada = filedialog.askdirectory(title="Selecione a pasta para verificar vírus")
    return pasta_selecionada

def calcular_hash(caminho_arquivo):
    """Gera o Hash SHA-256 do arquivo"""
    sha256 = hashlib.sha256()
    try:
        with open(caminho_arquivo, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                sha256.update(bloco)
        return sha256.hexdigest()
    except Exception as e:
        print(f" [!] Erro ao ler {os.path.basename(caminho_arquivo)}: {e}")
        return None

def consultar_virustotal(hash_arquivo):
    """Consulta a API do VirusTotal"""
    url = f"https://www.virustotal.com/api/v3/files/{hash_arquivo}"
    headers = {"x-apikey": API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            dados = response.json()
            stats = dados['data']['attributes']['last_analysis_stats']
            return stats['malicious'] # Retorna quantos acharam virus
        elif response.status_code == 404:
            return "Desconhecido" # Nunca foi escaneado
        elif response.status_code == 429:
            return "Limite Atingido"
        else:
            return f"Erro API: {response.status_code}"
            
    except Exception as e:
        return f"Erro Conexão: {e}"

def iniciar_scan():
    if API_KEY == "COLE_SUA_API_KEY_AQUI":
        print("ERRO: Você precisa colar sua API Key no código antes de rodar!")
        return

    pasta_alvo = selecionar_pasta()
    if not pasta_alvo:
        print("Nenhuma pasta selecionada. Encerrando.")
        return

    print(f"\n--- Iniciando Varredura em: {pasta_alvo} ---")
    print("Aviso: Devido ao plano gratuito, haverá uma pausa de 60s a cada 4 arquivos.\n")

    contador_arquivos = 0
    
    # Percorre todos os arquivos da pasta
    for raiz, _, arquivos in os.walk(pasta_alvo):
        for arquivo in arquivos:
            
            # VERIFICAÇÃO DO DELAY (A cada 4 arquivos)
            if contador_arquivos > 0 and contador_arquivos % 4 == 0:
                print(f"\n[PAUSA] 4 arquivos verificados. Aguardando 60 segundos pelo limite da API...")
                for i in range(60, 0, -1):
                    print(f"{i}...", end="\r")
                    time.sleep(1)
                print("Retomando...\n")

            caminho_completo = os.path.join(raiz, arquivo)
            nome_arquivo = arquivo
            
            print(f"Analisando: {nome_arquivo}...", end=" ")
            
            # 1. Calcula Hash
            file_hash = calcular_hash(caminho_completo)
            
            if file_hash:
                # 2. Consulta API
                resultado = consultar_virustotal(file_hash)
                
                # 3. Exibe Resultado
                if isinstance(resultado, int):
                    if resultado == 0:
                        print("✅ LIMPO")
                    elif resultado < 3:
                        print(f"⚠️ SUSPEITO ({resultado} detecções)")
                    else:
                        print(f"🚨 PERIGO! ({resultado} DETECÇÕES!)")
                else:
                    print(f"❓ {resultado}")
            
            contador_arquivos += 1

    print("\n--- Varredura Finalizada ---")

if __name__ == "__main__":
    iniciar_scan()