import os
import sys
import subprocess
import datetime

try:
    import requests
    import google.generativeai as genai
    import openai
except ImportError:
    print("Dependências não encontradas. Iniciando a instalação...")
    print("Isso pode levar alguns minutos...")
    required_packages = ['requests', 'google-generativeai', 'openai']
    
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *required_packages])
        print("Instalação concluída com sucesso. Por favor, reinicie o script.")
    except subprocess.CalledProcessError as e:
        print(f"Erro durante a instalação das dependências: {e}")
        print("Tente instalar manualmente: pip install -r requirements.txt")
    
    sys.exit()

GEMINI_PROVIDER = "gemini"
OPENAI_PROVIDER = "openai"

def getUserInput():
    """Coleta as configurações do usuário via terminal."""
    print("--- Configuração do Antivírus ---")
    
    apiProvider = input("Digite o provedor de IA (gemini ou openai): ").lower()
    if apiProvider not in [GEMINI_PROVIDER, OPENAI_PROVIDER]:
        print("Erro: Provedor de IA inválido. Por favor, escolha 'gemini' ou 'openai'.")
        return getUserInput()
        
    apiKey = input("Digite a sua chave de API: ")
    scanDirectory = input("Digite o diretório para escanear (padrão: .): ") or "."
    
    return {
        "apiProvider": apiProvider,
        "apiKey": apiKey,
        "scanDirectory": scanDirectory
    }

def analyzeWithGemini(fileContent, apiKey):
    """Analisa o conteúdo de um arquivo usando a API do Google Gemini."""
    try:
        genai.configure(api_key=apiKey)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        prompt = (
            "Analise o código. Identifique se é um malware, um código suspeito ou um código seguro. "
            "Se for um malware, diga o tipo (ex: web shell, backdoor) e o que ele faz. "
            "Em seguida, forneça 2-3 dicas curtas de remediação, focadas em ações do usuário (ex: remover, alterar senhas). "
            "Se for suspeito, explique o motivo em uma frase curta e forneça 2-3 dicas curtas de como melhorar a segurança. "
            "Se for seguro, diga apenas 'Código Seguro'. "
            "Mantenha a resposta curta, com no máximo 100 palavras."
            f"\n\nCódigo:\n{fileContent}"
        )
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Erro na API do Gemini: {e}"

def analyzeWithOpenAI(fileContent, apiKey):
    """Analisa o conteúdo de um arquivo usando a API da OpenAI."""
    try:
        openai.api_key = apiKey
        prompt = (
            "Analise o código. Identifique se é um malware, um código suspeito ou um código seguro. "
            "Se for um malware, diga o tipo (ex: web shell, backdoor) e o que ele faz. "
            "Em seguida, forneça 2-3 dicas curtas de remediação, focadas em ações do usuário (ex: remover, alterar senhas). "
            "Se for suspeito, explique o motivo em uma frase curta e forneça 2-3 dicas curtas de como melhorar a segurança. "
            "Se for seguro, diga apenas 'Código Seguro'. "
            "Mantenha a resposta curta, com no máximo 100 palavras."
            f"\n\nCódigo:\n{fileContent}"
        )
        response = openai.Completion.create(
            model="text-davinci-003",
            prompt=prompt,
            max_tokens=500
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"Erro na API da OpenAI: {e}"

def runScan():
    """Executa a rotina de varredura."""
    config = getUserInput()
    apiProvider = config.get('apiProvider')
    apiKey = config.get('apiKey')
    scanDirectory = config.get('scanDirectory')
    reportFile = "report.txt"

    malwaresFound = []
    suspectsFound = []
    totalFilesScanned = 0

    print(f"\nIniciando varredura em: {scanDirectory}...")

    for root, _, files in os.walk(scanDirectory):
        for fileName in files:
            filePath = os.path.join(root, fileName)
            totalFilesScanned += 1

            # Pular arquivos muito grandes ou não-código
            if not filePath.endswith(('.php', '.js', '.py', '.txt', '.html', '.css')) or os.path.getsize(filePath) > 200000:
                continue

            print(f"Analisando: {filePath}")

            try:
                with open(filePath, 'r', encoding='utf-8', errors='ignore') as file:
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
    
    if malwaresFound:
        removeMaliciousFiles(reportFile)

def generateReport(malwaresFound, suspectsFound, totalFilesScanned, reportFile):
    """Gera e salva o relatório final."""
    with open(reportFile, 'w') as report:
        report.write(f"Relatório de Varredura Antivírus - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write("---------------------------------------------------\n")
        report.write(f"Total de arquivos analisados: {totalFilesScanned}\n")
        report.write(f"Arquivos maliciosos encontrados: {len(malwaresFound)}\n")
        report.write(f"Arquivos suspeitos (possíveis falsos positivos): {len(suspectsFound)}\n\n")

        report.write("### Arquivos Maliciosos Encontrados\n")
        if not malwaresFound:
            report.write("Nenhum malware encontrado.\n\n")
        else:
            for malware in malwaresFound:
                report.write("---------------------------------------------------\n")
                report.write(f"Caminho do Arquivo: {malware['path']}\n")
                report.write(f"Análise da IA:\n{malware['analysis']}\n\n")

        report.write("### Arquivos Suspeitos (Possíveis Falsos Positivos)\n")
        if not suspectsFound:
            report.write("Nenhum arquivo suspeito encontrado.\n\n")
        else:
            for suspect in suspectsFound:
                report.write("---------------------------------------------------\n")
                report.write(f"Caminho do Arquivo: {suspect['path']}\n")
                report.write(f"Análise da IA:\n{suspect['analysis']}\n\n")

        report.write("---------------------------------------------------\n")
        report.write("Análise Concluída.\n")
    
    print("\nVarredura concluída. Verifique o arquivo de relatório.")

def removeMaliciousFiles(reportFile):
    """Lê o relatório e remove os arquivos maliciosos com a permissão do usuário."""
    with open(reportFile, 'r') as report:
        lines = report.readlines()
    
    maliciousFiles = []
    isMalwareSection = False
    
    for line in lines:
        if "### Arquivos Maliciosos Encontrados" in line:
            isMalwareSection = True
            continue
        if "### Arquivos Suspeitos" in line:
            isMalwareSection = False
            continue
        
        if isMalwareSection and "Caminho do Arquivo:" in line:
            filePath = line.split("Caminho do Arquivo:")[1].strip()
            maliciousFiles.append(filePath)
    
    if not maliciousFiles:
        print("Nenhum arquivo malicioso foi encontrado para remoção no relatório.")
        return

    print("\nOs seguintes arquivos serão removidos:")
    for file in maliciousFiles:
        print(f"- {file}")

    confirmation = input("\nDeseja continuar com a remoção? (s/n): ").lower()
    
    if confirmation in ["s", "sim"]:
        print("\nIniciando a remoção...")
        for file in maliciousFiles:
            try:
                os.remove(file)
                print(f"Arquivo removido com sucesso: {file}")
            except OSError as e:
                print(f"Erro ao remover o arquivo {file}: {e}")
        
        print("\nRemoção concluída.")
    else:
        print("Remoção cancelada pelo usuário.")

if __name__ == "__main__":
    print("--- Bem-vindo ao PrometheusAV ---")
    print("Selecione uma opção:")
    print("1. Iniciar uma nova varredura.")
    print("2. Remover arquivos maliciosos (baseado no último relatório).")
    
    choice = input("Digite 1 ou 2: ")
    
    if choice == "1":
        runScan()
    elif choice == "2":
        reportFile = "report.txt"
        if not os.path.exists(reportFile):
            print("Erro: O arquivo de relatório 'report.txt' não foi encontrado.")
            print("Por favor, execute uma varredura primeiro.")
        else:
            removeMaliciousFiles(reportFile)
    else:
        print("Opção inválida. O script será encerrado.")
