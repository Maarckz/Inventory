import os
import json
import bcrypt
import getpass
from dotenv import load_dotenv

# Carregar configurações do .env
load_dotenv()

# Configurações
AUTH_FILE = os.path.join(os.path.dirname(__file__), '../data/auth/logins.json')
MIN_PASSWORD_LENGTH = 8

def carregar_usuarios():
    """Carrega usuários do arquivo JSON"""
    try:
        os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
        if os.path.exists(AUTH_FILE):
            with open(AUTH_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except (json.JSONDecodeError, IOError) as e:
        print(f"Erro ao carregar usuários: {str(e)}")
        return []

def salvar_usuarios(usuarios):
    """Salva usuários no arquivo JSON"""
    try:
        with open(AUTH_FILE, 'w', encoding='utf-8') as f:
            json.dump(usuarios, f, ensure_ascii=False, indent=4)
        return True
    except IOError as e:
        print(f"Erro ao salvar usuários: {str(e)}")
        return False

def validar_senha(senha):
    """Valida a força da senha"""
    if len(senha) < MIN_PASSWORD_LENGTH:
        print(f"Senha muito curta! Mínimo de {MIN_PASSWORD_LENGTH} caracteres.")
        return False
        
    if not any(c.isupper() for c in senha):
        print("Senha deve conter pelo menos uma letra maiúscula")
        return False
        
    if not any(c.isdigit() for c in senha):
        print("Senha deve conter pelo menos um número")
        return False
        
    return True

def criar_usuario():
    """Cria um novo usuário"""
    usuarios = carregar_usuarios()
    
    print("\n--- CRIAR NOVO USUÁRIO ---")
    username = input("Nome de usuário: ").strip()
    
    # Verificar se usuário já existe
    if any(u['username'] == username for u in usuarios):
        print("Erro: Este usuário já existe!")
        return
    
    # Obter senha de forma segura
    while True:
        senha = getpass.getpass("Senha: ").strip()
        confirmacao = getpass.getpass("Confirme a senha: ").strip()
        
        if senha != confirmacao:
            print("Erro: As senhas não coincidem!")
            continue
            
        if validar_senha(senha):
            break
    
    # Criar hash seguro da senha
    hashed = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Adicionar novo usuário
    novo_usuario = {
        'username': username,
        'password_hash': hashed
    }
    usuarios.append(novo_usuario)
    
    # Salvar alterações
    if salvar_usuarios(usuarios):
        print(f"\nUsuário '{username}' criado com sucesso!")
    else:
        print("\nErro ao salvar usuário!")

def remover_usuario():
    """Remove um usuário existente"""
    usuarios = carregar_usuarios()
    
    print("\n--- REMOVER USUÁRIO ---")
    if not usuarios:
        print("Nenhum usuário cadastrado!")
        return
    
    # Listar usuários
    print("\nUsuários cadastrados:")
    for i, usuario in enumerate(usuarios, 1):
        print(f"{i}. {usuario['username']}")
    
    try:
        escolha = int(input("\nSelecione o número do usuário a remover (0 para cancelar): "))
        if escolha == 0:
            return
            
        usuario = usuarios[escolha-1]
    except (ValueError, IndexError):
        print("Seleção inválida!")
        return
    
    # Confirmar remoção
    confirmacao = input(f"\nTem certeza que deseja remover o usuário '{usuario['username']}'? (s/n): ").lower()
    if confirmacao != 's':
        print("Operação cancelada!")
        return
    
    # Remover usuário
    del usuarios[escolha-1]
    
    # Salvar alterações
    if salvar_usuarios(usuarios):
        print(f"\nUsuário '{usuario['username']}' removido com sucesso!")
    else:
        print("\nErro ao remover usuário!")

def listar_usuarios():
    """Lista todos os usuários"""
    usuarios = carregar_usuarios()
    
    print("\n--- USUÁRIOS CADASTRADOS ---")
    if not usuarios:
        print("Nenhum usuário cadastrado!")
        return
    
    for i, usuario in enumerate(usuarios, 1):
        print(f"{i}. {usuario['username']}")
    
    print(f"\nTotal: {len(usuarios)} usuário(s)")

def alterar_senha():
    """Altera a senha de um usuário"""
    usuarios = carregar_usuarios()
    
    print("\n--- ALTERAR SENHA ---")
    if not usuarios:
        print("Nenhum usuário cadastrado!")
        return
    
    # Listar usuários
    print("\nUsuários cadastrados:")
    for i, usuario in enumerate(usuarios, 1):
        print(f"{i}. {usuario['username']}")
    
    try:
        escolha = int(input("\nSelecione o número do usuário (0 para cancelar): "))
        if escolha == 0:
            return
            
        usuario = usuarios[escolha-1]
    except (ValueError, IndexError):
        print("Seleção inválida!")
        return
    
    # Obter nova senha
    while True:
        nova_senha = getpass.getpass("Nova senha: ").strip()
        confirmacao = getpass.getpass("Confirme a nova senha: ").strip()
        
        if nova_senha != confirmacao:
            print("Erro: As senhas não coincidem!")
            continue
            
        if validar_senha(nova_senha):
            break
    
    # Atualizar senha
    usuario['password_hash'] = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    # Salvar alterações
    if salvar_usuarios(usuarios):
        print(f"\nSenha do usuário '{usuario['username']}' alterada com sucesso!")
    else:
        print("\nErro ao alterar senha!")

def mostrar_menu():
    """Exibe o menu de opções"""
    print("\n" + "="*40)
    print("GERENCIADOR DE USUÁRIOS")
    print("="*40)
    print("1. Adicionar usuário")
    print("2. Remover usuário")
    print("3. Listar usuários")
    print("4. Alterar senha")
    print("5. Sair")
    print("="*40)
    
    try:
        return int(input("Selecione uma opção: "))
    except ValueError:
        return -1

def main():
    """Função principal"""
    # Verificar se bcrypt está instalado
    try:
        bcrypt.gensalt()
    except:
        print("Erro: Biblioteca bcrypt não instalada!")
        print("Instale com: pip install bcrypt")
        return
    
    # Verificar se o diretório existe
    os.makedirs(os.path.dirname(AUTH_FILE), exist_ok=True)
    
    while True:
        opcao = mostrar_menu()
        
        if opcao == 1:
            criar_usuario()
        elif opcao == 2:
            remover_usuario()
        elif opcao == 3:
            listar_usuarios()
        elif opcao == 4:
            alterar_senha()
        elif opcao == 5:
            print("\nSaindo do sistema...")
            break
        else:
            print("\nOpção inválida! Tente novamente.")
        
        input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    main()