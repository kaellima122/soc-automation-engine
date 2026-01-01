import os
import hashlib
import time
import requests
import csv
import shutil
import logging
from dotenv import load_dotenv # Melhoria de Segurança
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# --- CONFIGURAÇÃO DE LOGGING PROFISSIONAL ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("soc_enterprise.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)

# Carregar variáveis de ambiente
load_dotenv()

# --- CONFIGURAÇÕES DE GOVERNANÇA ---
VT_API_KEY = os.getenv("VT_API_KEY") 
PASTA_BASE_RELATORIOS = "./relatorios_incidentes"
PASTA_QUARENTENA = "./quarentena"
PASTA_COPIAS_AMOSTRAS = "./copias_amostras"
ARQUIVO_INDICE = os.path.join(PASTA_BASE_RELATORIOS, "BUSCA_RAPIDA_INDICE.csv")

# Controle de Duplicidade (Thread-Safe)
arquivos_em_processamento = set() 
hashes_processados = {}

# --- MODELO DE DADOS (DOMÍNIO) ---
class Incidente:
    def __init__(self, arquivo_path):
        self.id = f"INC-{int(time.time())}"
        self.arquivo_original = os.path.basename(arquivo_path)
        self.caminho_original = arquivo_path
        self.hash = ""
        self.malicious_count = 0
        self.veredito = ""
        self.data_extensa = time.strftime("%Y/%m/%d")
        self.data_csv = time.strftime("%d/%m/%Y")
        self.hora_csv = time.strftime("%H:%M:%S")

# --- SERVIÇOS TÉCNICOS ---

class ScannerService:
    @staticmethod
    def calcular_sha256(caminho):
        sha = hashlib.sha256()
        try:
            with open(caminho, "rb") as f:
                for bloco in iter(lambda: f.read(4096), b""): sha.update(bloco)
            return sha.hexdigest()
        except IOError as e:
            logging.error(f"Erro de I/O ao calcular hash: {e}")
            return None

    @staticmethod
    def consultar_threat_intel(file_hash):
        if not VT_API_KEY:
            logging.critical("VT_API_KEY não configurada no arquivo .env")
            return None
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logging.error("Chave de API do VirusTotal inválida ou expirada.")
            return None
        except requests.RequestException as e:
            logging.error(f"Falha na comunicação com VirusTotal: {e}")
            return None

class InteligenciaIA:
    @staticmethod
    def gerar_analise(incidente, tipo="TECNICO"):
        if incidente.malicious_count == 0:
            contexto = "INTEGRIDADE CONFIRMADA: Ativo sem ameaças identificadas."
            objetivo = "Confirmar segurança e autorizar continuidade operacional."
        else:
            contexto = f"AMEAÇA IDENTIFICADA: Detectado artefato com {incidente.malicious_count} assinaturas maliciosas."
            objetivo = "Descrever riscos à infraestrutura e protocolos de mitigação."

        persona = "CISO" if tipo == "EXECUTIVO" else "Especialista Tier 3"
        
        prompt = f"""
        SISTEMA SOC - RELATÓRIO {incidente.id}
        AUTOR: {persona} | STATUS: {incidente.veredito}
        DADOS: {incidente.arquivo_original} | CONTEXTO: {contexto}
        TAREFA: {objetivo}
        REGRAS: Tom CORPORATIVO e DIRETO. Sem saudações. Responda em Português-BR. Máximo 4 frases.
        """
        try:
            res = requests.post("http://localhost:11434/api/generate", 
                                json={"model": "llama3", "prompt": prompt, "stream": False}, timeout=45)
            return res.json().get("response", "Motor de IA indisponível.").strip()
        except Exception as e:
            logging.warning(f"Falha ao gerar relatório IA: {e}")
            return "Parecer técnico não gerado por indisponibilidade do motor de IA."

# --- MÓDULO DE AUDITORIA ---

def buscar_relatorios():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*80)
        print("          CENTRAL DE AUDITORIA E BUSCA DE INCIDENTES - SOC v5.0")
        print("="*80)
        print("1. Filtrar por ID | 2. Filtrar por DATA (DD/MM/YY) | 3. Filtrar por NOME | 0. Sair")
        
        op = input("\nSelecione o filtro: ")
        if op == "0": break
        if op not in ["1", "2", "3"]: continue
        
        termo = input("Digite o termo de busca: ").strip()
        
        # NORMALIZAÇÃO DE DATA (v5.0 fix)
        if op == "2" and "/" in termo:
            partes = termo.split('/')
            if len(partes) == 3 and len(partes[2]) == 2:
                termo = f"{partes[0]}/{partes[1]}/20{partes[2]}"

        resultados = []
        try:
            with open(ARQUIVO_INDICE, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f, delimiter=';')
                for linha in reader:
                    match = False
                    if op == "1" and termo.upper() in linha['ID'].upper(): match = True
                    elif op == "2" and termo in linha['DATA']: match = True
                    elif op == "3" and termo.lower() in linha['ARQUIVO'].lower(): match = True
                    if match: resultados.append(linha)
        except Exception as e:
            logging.error(f"Erro ao acessar base de dados: {e}")
            continue

        resultados.reverse()
        if resultados:
            print(f"\n{'ID':<18} | {'DATA':<12} | {'ARQUIVO':<25} | {'VEREDITO':<20}")
            print("-" * 85)
            for r in resultados:
                print(f"{r['ID']:<18} | {r['DATA']:<12} | {r['ARQUIVO'][:25]:<25} | {r['RISCO']:<20}")
            
            detalhe = input("\nDigite o ID para ver caminhos locais ou ENTER para voltar: ").strip()
            if detalhe:
                for r in resultados:
                    if detalhe.upper() in r['ID'].upper():
                        d, m, a = r['DATA'].split('/')
                        p_rel = os.path.join(PASTA_BASE_RELATORIOS, "TECNICO", a, m, d, r['ID'])
                        p_cop = os.path.join(PASTA_COPIAS_AMOSTRAS, a, m, d, r['ID'])
                        print(f"\n[+] LAUDO TÉCNICO: {os.path.abspath(p_rel)}")
                        print(f"[+] AMOSTRA ORIGINAL: {os.path.abspath(p_cop)}")
                        input("\nPressione ENTER...")
        else:
            print(f"\n[-] Nenhum registro localizado para: {termo}"); time.sleep(2)

# --- MONITORAMENTO REAL-TIME ---

class SOCHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory: return
        path = event.src_path
        if path in arquivos_em_processamento: return
        arquivos_em_processamento.add(path)

        try:
            time.sleep(2.5) # Aguarda estabilização do arquivo
            if not os.path.exists(path): return
            
            h = ScannerService.calcular_sha256(path)
            if not h: return
            
            agora = time.time()
            if h in hashes_processados and (agora - hashes_processados[h]) < 60: return
            hashes_processados[h] = agora

            inc = Incidente(path)
            inc.hash = h
            logging.info(f"Iniciando análise do ativo: {inc.arquivo_original} [{inc.id}]")

            data_vt = ScannerService.consultar_threat_intel(h)
            inc.malicious_count = data_vt['data']['attributes']['last_analysis_stats']['malicious'] if data_vt else 0
            inc.veredito = "CRÍTICO - MALICIOSO" if inc.malicious_count > 0 else "CONFORMIDADE - LIMPO"

            # Gestão de Pastas e Isolamento
            p_rel = os.path.join(PASTA_BASE_RELATORIOS, "TECNICO", inc.data_extensa, inc.id)
            p_cop = os.path.join(PASTA_COPIAS_AMOSTRAS, inc.data_extensa, inc.id)
            os.makedirs(p_rel, exist_ok=True)
            os.makedirs(p_cop, exist_ok=True)

            shutil.move(path, os.path.join(p_cop, inc.arquivo_original))

            # Geração de Laudos
            txt_tec = InteligenciaIA.gerar_analise(inc, "TECNICO")
            with open(os.path.join(p_rel, "RELATORIO_TECNICO.txt"), "w", encoding="utf-8") as f:
                f.write(f"SISTEMA SOC - LAUDO {inc.id}\nATIVO: {inc.arquivo_original}\nSTATUS: {inc.veredito}\n\n{txt_tec}")

            if inc.malicious_count > 0:
                p_exe = os.path.join(PASTA_BASE_RELATORIOS, "EXECUTIVO", inc.data_extensa, inc.id)
                os.makedirs(p_exe, exist_ok=True)
                txt_exe = InteligenciaIA.gerar_analise(inc, "EXECUTIVO")
                with open(os.path.join(p_exe, "RESUMO_EXECUTIVO.txt"), "w", encoding="utf-8") as f:
                    f.write(f"RESUMO ESTRATÉGICO {inc.id}\nSTATUS: {inc.veredito}\n\n{txt_exe}")

            # Persistência
            with open(ARQUIVO_INDICE, "a", encoding="utf-8") as f:
                f.write(f"{inc.id};{inc.data_csv};{inc.hora_csv};{inc.arquivo_original};{inc.veredito};{inc.malicious_count}\n")
            
            logging.info(f"Concluído: {inc.id} | Status: {inc.veredito}")

        except Exception as e:
            logging.error(f"Falha crítica no ativo {path}: {e}")
        finally:
            if path in arquivos_em_processamento: arquivos_em_processamento.remove(path)

# --- BOOT ---

if __name__ == "__main__":
    for p in [PASTA_QUARENTENA, PASTA_BASE_RELATORIOS, PASTA_COPIAS_AMOSTRAS]:
        os.makedirs(p, exist_ok=True)

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print("="*60)
        print("           SISTEMA DE SEGURANÇA CORPORATIVA SOC PRO v5.0")
        print("="*60)
        print("1. ATIVAR MONITORAMENTO REAL-TIME")
        print("2. ACESSAR AUDITORIA DE INCIDENTES")
        print("0. ENCERRAR SISTEMA")
        print("="*60)
        
        escolha = input("\nSelecione uma operação: ")

        if escolha == "1":
            obs = Observer()
            obs.schedule(SOCHandler(), PASTA_QUARENTENA, recursive=False)
            obs.start()
            logging.info("Monitoramento de infraestrutura ativado.")
            try:
                while True: time.sleep(1)
            except KeyboardInterrupt:
                obs.stop()
            obs.join()
        elif escolha == "2":
            buscar_relatorios()
        elif escolha == "0":
            break