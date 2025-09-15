import os
import json
import requests
import google.generativeai as genai
import openai
import datetime

GEMINI_PROVIDER = "gemini"
OPENAI_PROVIDER = "openai"

API_ERROR_MESSAGE = "Erro ao conectar à API de IA. Verifique a chave e o provedor no arquivo config.json."

def loadConfig():
    """Carrega as configurações do arquivo config.json."""
    try:
        with open('config.json', 'r') as configFile:
            config = json.load(configFile)
        return config
    except FileNotFoundError:
        print("Erro: O arquivo 'config.json' não foi encontrado.")
        exit()

def analyzeWithGemini(fileContent, apiKey):
    """Analisa o conteúdo de um arquivo usando a API do Google Gemini."""
    try:
        genai.configure(api_key=apiKey)
        model = genai.GenerativeModel('gemini-pro')
        prompt = (
            "Analise este código e identifique se ele é um malware, um código suspeito ou um código seguro. "
            "Se for ummalware, diga o tipo (ex: web shell, backdoor, phishing, etc) e as linhas suspeitas. "
            "Se for suspeito, explique o por que. "
            "Se for seguro, diga apenas 'Código Seguro'. "
            "Para malwares e suspeitos, forneça dicas sucintas de como tratar o problema. "
            "Responda usando as categorias: 'MALWARE', 'SUSPEITO' ou 'SEGURO'. \n\n"
            f"Código:\n{fileContent}"
        )
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Erro na API do Gemini: {e}")
        return API_ERROR_MESSAGE

def analyzeWithOpenAI(fileContent, apiKey):
    """Analisa o conteúdo de um arquivo usando a API da OpenAI."""
    try:
        openai.api_key = apiKey
        prompt = (
            "Analise este código e identifique se ele é um malware, um código suspeito ou um código seguro. "
            "Se for um malware, diga o tipo (ex: web shell, backdoor, phishing, etc) e as linhas suspeitas. "
            "Se for suspeito, explique o por que. "
            "Se for seguro, diga apenas 'Código Seguro'. "
            "Para malwares e suspeitos, forneça dicas sucintas de como tratar o problema. "
            "Responda usando as categorias: 'MALWARE', 'SUSPEITO' ou 'SEGURO'. \n\n"
            f"Código:\n{fileContent}"
        )
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=prompt,
            max_tokens=500
        )
        return response.choices[0].text.strip()
    except Exception as e:
        print(f"Erro na API da OpenAI: {e}")
        return API_ERROR_MESSAGE
    
def runScan():
    """Executa a rotina de varredura."""
    config = loadConfig()
    apiProvider = config.get('apiProvider')
    apiKey = config.get('apiKey')
    scanDirectory = config.get('scanDirectory')
    reportFile = config.get('reportFile')

    if not apiKey or apiKey == "SUA_CHAVE_DE_API_AQUI":
        print("Erro: A chave de API não foi configurada corretamente no arquivo 'config.json'. ")
        return
    
    malwaresFound = []
    suspectsFound = []
    totalFilesScanned = 0

    print(f"Iniciando varredura em: {scanDirectory}...")

    for root, _, files in os.walk(scanDirectory):
        for fileName in files:
            filePath = os.path.join(root, fileName)
            totalFilesScanned += 1
            print(f"Analisando: {filePath}")

            if not filePath.endswith(('.php', '.js', '.py', '.txt', '.html', '.css')) or os.path.getsize(filePath) > 200000:
                continue
            
            try:
                with open (filePath, 'r', encoding='utf-8', errors='ignore') as file:
                    fileContent = file.read()

                analysisResult = ""
                if apiProvider == GEMINI_PROVIDER:
                    analysisResult = analyzeWithGemini(fileContent, apiKey)
                elif apiProvider == OPENAI_PROVIDER:
                    analysisResult = analyzeWithOpenAI(fileContent, apiKey)

                if "MALWARE" in analysisResult.upper():
                    malwaresFound.append({'path': filePath, 'analysis': analysisResult})
                elif "SUSPEITO" in analysisResult.upper():
                    suspectsFound.append({'path': filePath, 'analysis': analysisResult})
            except Exception as e:
                print(f"Erro ao ler o arquivo {filePath}: {e}")

    generateReport(malwaresFound, suspectsFound, totalFilesScanned, reportFile)
    print("Varredura concluída. Verifique o arquivo 'report.txt'.")

def generateReport(malwaresFound, suspectsFound, totalFilesScanned, reportFile):
    """Gera e salva o relatório final."""
    with open(reportFile, 'w') as report:
        report.write(f"Relatório de Varredura Antivírus - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write("---------------------------------------------------\n")
        report.write(f"Total de arquivos analisados: {totalFilesScanned}\n")
        report.write(f"Arquivos maliciosos encontrados: {len(malwaresFound)}\n")
        report.write(f"Arquivos suspeitos (possíveis falsos positivos): {len(suspectsFound)}\n\n")

        # Malwares encontrados
        report.write("### Arquivos Maliciosos Encontrados\n")
        if not malwaresFound:
            report.write("Nenhum malware encontrado.\n\n")
        else:
            for malware in malwaresFound:
                report.write(f"---------------------------------------------------\n")
                report.write(f"Caminho do Arquivo: {malware['path']}\n")
                report.write(f"Análise da IA:\n{malware['analysis']}\n\n")

        # Arquivos suspeitos
        report.write("### Arquivos Suspeitos (Possíveis Falsos Positivos)\n")
        if not suspectsFound:
            report.write("Nenhum arquivo suspeito encontrado.\n\n")
        else:
            for suspect in suspectsFound:
                report.write(f"---------------------------------------------------\n")
                report.write(f"Caminho do Arquivo: {suspect['path']}\n")
                report.write(f"Análise da IA:\n{suspect['analysis']}\n\n")

        report.write("---------------------------------------------------\n")
        report.write("Análise Concluída.\n")

if __name__ == "__main__":
    runScan()