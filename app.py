"""
Interface Streamlit para SecureFileKit
Sistema de criptografia, decriptografia e hash para arquivos.
"""

import streamlit as st
import tempfile
import os
import json
from pathlib import Path
import io
from securefilekit.__main__ import (
    gen_sym_key, load_sym_key, enc_sym, dec_sym,
    gen_keypair, enc_asym, dec_asym, do_hash
)

# Configuração da página
st.set_page_config(
    page_title="SecureFileKit",
    page_icon=None,
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS customizado
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .feature-box {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        color: #155724;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #c3e6cb;
    }
    .error-box {
        background-color: #f8d7da;
        color: #721c24;
        padding: 1rem;
        border-radius: 0.5rem;
        border: 1px solid #f5c6cb;
    }
    /* Esconder textos dos file_uploaders mas manter botões */
    div[data-testid="stFileUploader"] p {
        display: none !important;
    }
    div[data-testid="stFileUploader"] small {
        display: none !important;
    }
    /* Esconder área de drag and drop mas manter botão Browse files */
    div[data-testid="stFileUploader"] > div > div:first-child > div:first-child {
        display: none !important;
    }
    /* Esconder texto "Drag and drop file here" */
    div[data-baseweb="file-uploader"] > div:first-child {
        display: none !important;
    }
    /* Esconder limite de tamanho */
    div[data-testid="stFileUploader"] small[data-testid="stMarkdownContainer"] {
        display: none !important;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Cabeçalho
    st.markdown('<div class="main-header">SecureFileKit</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="text-align: center; color: #666; margin-bottom: 2rem;">
        Sistema de criptografia, decriptografia e hash para qualquer tipo de arquivo
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar com informações
    with st.sidebar:
        st.header("Sobre")
        st.markdown("""
        **SecureFileKit** oferece:
        - Criptografia simétrica (AES-256-GCM)
        - Criptografia assimétrica (RSA-4096 + OAEP)
        - Geração de hash (SHA-256)
        - Suporte para qualquer tipo de arquivo
        """)
        
        st.header("Segurança")
        st.markdown("""
        - AES-256-GCM com nonce aleatório
        - RSA-4096 com OAEP-SHA-256
        - Criptografia híbrida para arquivos grandes
        - Sem uso de algoritmos inseguros
        """)
        
        st.header("Formatos")
        st.markdown("""
        - **.sim** → Criptografia simétrica
        - **.asi** → Criptografia assimétrica
        - **.has** → Arquivo de hash
        """)
    
    # Menu principal
    menu = st.selectbox(
        "Selecione a operação:",
        [
            "Gerar Chaves",
            "Criptografia Simétrica",
            "Decriptografia Simétrica",
            "Criptografia Assimétrica",
            "Decriptografia Assimétrica",
            "Gerar Hash"
        ]
    )
    
    # Container principal
    with st.container():
        if menu == "Gerar Chaves":
            st.header("Geração de Chaves")
            
            tab1, tab2 = st.tabs(["Chave Simétrica (AES-256)", "Par de Chaves RSA (4096 bits)"])
            
            with tab1:
                st.subheader("Gerar Chave Simétrica")
                st.info("Uma chave AES-256 será gerada e salva em formato JSON.")
                
                # Inicializar session_state se não existir
                if 'sym_key_data' not in st.session_state:
                    st.session_state.sym_key_data = None
                
                if st.button("Gerar Chave Simétrica", type="primary"):
                    try:
                        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
                            tmp_path = tmp.name
                        
                        gen_sym_key(tmp_path)
                        
                        with open(tmp_path, 'r') as f:
                            st.session_state.sym_key_data = f.read()
                        
                        os.unlink(tmp_path)
                        
                        st.success("Chave simétrica gerada com sucesso!")
                    except Exception as e:
                        st.error(f"Erro ao gerar chave: {str(e)}")
                        st.session_state.sym_key_data = None
                
                # Mostrar botão de download se a chave foi gerada
                if st.session_state.sym_key_data:
                    st.download_button(
                        label="Baixar Chave",
                        data=st.session_state.sym_key_data,
                        file_name="key_aes.json",
                        mime="application/json",
                        key="download_sym_key"
                    )
                    
                    # Botão para gerar nova chave
                    if st.button("Gerar Nova Chave", help="Limpa a chave atual e permite gerar uma nova"):
                        st.session_state.sym_key_data = None
                        st.rerun()
            
            with tab2:
                st.subheader("Gerar Par de Chaves RSA")
                st.info("Um par de chaves RSA-4096 será gerado (privada e pública).")
                
                # Inicializar session_state se não existir
                if 'rsa_priv_data' not in st.session_state:
                    st.session_state.rsa_priv_data = None
                if 'rsa_pub_data' not in st.session_state:
                    st.session_state.rsa_pub_data = None
                
                use_passphrase = st.checkbox("Proteger chave privada com senha")
                passphrase = None
                if use_passphrase:
                    passphrase = st.text_input("Senha para chave privada:", type="password")
                
                if st.button("Gerar Par de Chaves", type="primary"):
                    if use_passphrase and not passphrase:
                        st.warning("Por favor, insira uma senha para proteger a chave privada.")
                    else:
                        try:
                            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as tmp_priv:
                                priv_path = tmp_priv.name
                            with tempfile.NamedTemporaryFile(mode='wb', suffix='.pem', delete=False) as tmp_pub:
                                pub_path = tmp_pub.name
                            
                            gen_keypair(priv_path, pub_path, passphrase)
                            
                            with open(priv_path, 'rb') as f:
                                st.session_state.rsa_priv_data = f.read()
                            with open(pub_path, 'rb') as f:
                                st.session_state.rsa_pub_data = f.read()
                            
                            os.unlink(priv_path)
                            os.unlink(pub_path)
                            
                            st.success("Par de chaves gerado com sucesso!")
                        except Exception as e:
                            st.error(f"Erro ao gerar par de chaves: {str(e)}")
                            st.session_state.rsa_priv_data = None
                            st.session_state.rsa_pub_data = None
                
                # Mostrar botões de download se as chaves foram geradas
                if st.session_state.rsa_priv_data and st.session_state.rsa_pub_data:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.download_button(
                            label="Baixar Chave Privada",
                            data=st.session_state.rsa_priv_data,
                            file_name="rsa_private.pem",
                            mime="application/x-pem-file",
                            key="download_priv"
                        )
                    with col2:
                        st.download_button(
                            label="Baixar Chave Pública",
                            data=st.session_state.rsa_pub_data,
                            file_name="rsa_public.pem",
                            mime="application/x-pem-file",
                            key="download_pub"
                        )
                    
                    # Botão para limpar/gerar novas chaves
                    if st.button("Gerar Novo Par de Chaves", help="Limpa as chaves atuais e permite gerar novas"):
                        st.session_state.rsa_priv_data = None
                        st.session_state.rsa_pub_data = None
                        st.rerun()
        
        elif menu == "Criptografia Simétrica":
            st.header("Criptografia Simétrica (AES-256-GCM)")
            st.info("Criptografa um arquivo usando uma chave simétrica. O resultado será um arquivo .sim")
            
            key_file = st.file_uploader("Chave Simétrica (JSON)", type=['json'], help="Faça upload de um arquivo JSON com a chave simétrica (ex: key_aes.json)")
            input_file = st.file_uploader("Arquivo para Criptografar", type=None)
            
            # Mostrar status dos uploads
            if key_file is not None:
                # Verificar se é realmente um JSON
                try:
                    key_file.seek(0)  # Resetar ponteiro
                    key_content = key_file.read()
                    key_file.seek(0)  # Resetar novamente para uso posterior
                    json.loads(key_content.decode('utf-8'))
                    st.success(f"Chave carregada: {key_file.name}")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    st.error(f"Erro: {key_file.name} não é um arquivo JSON válido. Use uma chave simétrica gerada pela interface (key_aes.json).")
                except Exception:
                    st.success(f"Chave carregada: {key_file.name}")
            
            if input_file is not None:
                try:
                    input_file.seek(0)
                    file_size = len(input_file.read())
                    input_file.seek(0)
                    st.success(f"Arquivo carregado: {input_file.name} ({file_size} bytes)")
                except Exception:
                    st.success(f"Arquivo carregado: {input_file.name}")
            
            if st.button("Criptografar", type="primary"):
                if key_file is None or input_file is None:
                    missing = []
                    if key_file is None:
                        missing.append("chave simétrica (JSON)")
                    if input_file is None:
                        missing.append("arquivo para criptografar")
                    st.warning(f"Por favor, faça upload: {', '.join(missing)}.")
                else:
                    try:
                        # Resetar ponteiros dos arquivos
                        key_file.seek(0)
                        input_file.seek(0)
                        
                        # Salvar arquivos temporários
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_key:
                            tmp_key.write(key_file.read())
                            tmp_key_path = tmp_key.name
                        
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_input:
                            tmp_input.write(input_file.read())
                            tmp_input_path = tmp_input.name
                        
                        output_path = tmp_input_path + ".sim"
                        
                        enc_sym(tmp_key_path, tmp_input_path, output_path)
                        
                        with open(output_path, 'rb') as f:
                            encrypted_data = f.read()
                        
                        st.success("Arquivo criptografado com sucesso!")
                        st.download_button(
                            label="Baixar Arquivo Criptografado",
                            data=encrypted_data,
                            file_name=input_file.name + ".sim",
                            mime="application/octet-stream"
                        )
                        
                        # Limpar arquivos temporários
                        os.unlink(tmp_key_path)
                        os.unlink(tmp_input_path)
                        os.unlink(output_path)
                    except Exception as e:
                        st.error(f"Erro ao criptografar: {str(e)}")
        
        elif menu == "Decriptografia Simétrica":
            st.header("Decriptografia Simétrica")
            st.info("Descriptografa um arquivo .sim usando a chave simétrica.")
            
            key_file = st.file_uploader("Chave Simétrica (JSON)", type=['json'])
            encrypted_file = st.file_uploader("Arquivo Criptografado (.sim)", type=None, help="Selecione o arquivo .sim criptografado")
            
            if st.button("Decriptografar", type="primary"):
                if not key_file or not encrypted_file:
                    st.warning("Por favor, faça upload da chave e do arquivo criptografado.")
                else:
                    try:
                        # Salvar arquivos temporários
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_key:
                            tmp_key.write(key_file.read())
                            tmp_key_path = tmp_key.name
                        
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.sim') as tmp_enc:
                            tmp_enc.write(encrypted_file.read())
                            tmp_enc_path = tmp_enc.name
                        
                        output_path = tmp_enc_path.replace('.sim', '.dec')
                        
                        dec_sym(tmp_key_path, tmp_enc_path, output_path)
                        
                        with open(output_path, 'rb') as f:
                            decrypted_data = f.read()
                        
                        st.success("Arquivo descriptografado com sucesso!")
                        
                        # Tentar determinar o nome original
                        original_name = encrypted_file.name.replace('.sim', '')
                        st.download_button(
                            label="Baixar Arquivo Descriptografado",
                            data=decrypted_data,
                            file_name=original_name,
                            mime="application/octet-stream"
                        )
                        
                        # Limpar arquivos temporários
                        os.unlink(tmp_key_path)
                        os.unlink(tmp_enc_path)
                        os.unlink(output_path)
                    except Exception as e:
                        st.error(f"Erro ao descriptografar: {str(e)}")
        
        elif menu == "Criptografia Assimétrica":
            st.header("Criptografia Assimétrica (RSA-4096 + AES-GCM)")
            st.info("Criptografa um arquivo usando a chave pública RSA. O resultado será um arquivo .asi")
            st.warning("IMPORTANTE: Use a chave PÚBLICA (rsa_public.pem) para criptografar. A chave pública NÃO tem senha.")
            
            pub_key_file = st.file_uploader("Chave Pública RSA (.pem)", type=['pem'], help="Use o arquivo rsa_public.pem (não a chave privada)")
            input_file = st.file_uploader("Arquivo para Criptografar", type=None)
            
            if st.button("Criptografar", type="primary"):
                if not pub_key_file or not input_file:
                    st.warning("Por favor, faça upload da chave pública e do arquivo.")
                else:
                    try:
                        # Salvar arquivos temporários
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as tmp_pub:
                            tmp_pub.write(pub_key_file.read())
                            tmp_pub_path = tmp_pub.name
                        
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_input:
                            tmp_input.write(input_file.read())
                            tmp_input_path = tmp_input.name
                        
                        output_path = tmp_input_path + ".asi"
                        
                        enc_asym(tmp_pub_path, tmp_input_path, output_path)
                        
                        with open(output_path, 'rb') as f:
                            encrypted_data = f.read()
                        
                        st.success("Arquivo criptografado com sucesso!")
                        st.download_button(
                            label="Baixar Arquivo Criptografado",
                            data=encrypted_data,
                            file_name=input_file.name + ".asi",
                            mime="application/json"
                        )
                        
                        # Limpar arquivos temporários
                        os.unlink(tmp_pub_path)
                        os.unlink(tmp_input_path)
                        os.unlink(output_path)
                    except ValueError as e:
                        error_msg = str(e)
                        if "private" in error_msg.lower() or "encryption" in error_msg.lower():
                            st.error("Erro: Você está tentando usar a chave PRIVADA. Para criptografar, use a chave PÚBLICA (rsa_public.pem). A chave pública não requer senha.")
                        else:
                            st.error(f"Erro ao criptografar: {error_msg}")
                    except Exception as e:
                        error_msg = str(e)
                        if "private" in error_msg.lower() or "encryption" in error_msg.lower():
                            st.error("Erro: Você está tentando usar a chave PRIVADA. Para criptografar, use a chave PÚBLICA (rsa_public.pem).")
                        else:
                            st.error(f"Erro ao criptografar: {error_msg}")
        
        elif menu == "Decriptografia Assimétrica":
            st.header("Decriptografia Assimétrica")
            st.info("Descriptografa um arquivo .asi usando a chave privada RSA.")
            
            priv_key_file = st.file_uploader("Chave Privada RSA (.pem)", type=['pem'], help="Use o arquivo rsa_private.pem")
            encrypted_file = st.file_uploader("Arquivo Criptografado (.asi)", type=None, help="Selecione o arquivo .asi criptografado")
            
            # Campo de senha sempre visível, mas opcional
            st.markdown("**Senha da chave privada (se aplicável):**")
            passphrase = st.text_input(
                "Digite a senha se a chave privada foi protegida com senha ao ser gerada:",
                type="password",
                help="Deixe em branco se a chave não tem senha",
                label_visibility="visible"
            )
            if not passphrase:
                st.caption("Dica: Se você gerou a chave com senha, digite-a acima. Caso contrário, deixe em branco.")
            
            if st.button("Decriptografar", type="primary"):
                if not priv_key_file or not encrypted_file:
                    st.warning("Por favor, faça upload da chave privada e do arquivo criptografado.")
                else:
                    try:
                        # Salvar arquivos temporários
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as tmp_priv:
                            tmp_priv.write(priv_key_file.read())
                            tmp_priv_path = tmp_priv.name
                        
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.asi') as tmp_enc:
                            tmp_enc.write(encrypted_file.read())
                            tmp_enc_path = tmp_enc.name
                        
                        output_path = tmp_enc_path.replace('.asi', '.dec')
                        
                        # Tentar descriptografar
                        # Se a senha estiver vazia, passamos None; caso contrário, passamos a senha
                        passphrase_to_use = passphrase if passphrase else None
                        
                        dec_asym(tmp_priv_path, tmp_enc_path, output_path, passphrase_to_use)
                        
                        with open(output_path, 'rb') as f:
                            decrypted_data = f.read()
                        
                        st.success("Arquivo descriptografado com sucesso!")
                        
                        # Tentar determinar o nome original
                        original_name = encrypted_file.name.replace('.asi', '')
                        st.download_button(
                            label="Baixar Arquivo Descriptografado",
                            data=decrypted_data,
                            file_name=original_name,
                            mime="application/octet-stream"
                        )
                        
                        # Limpar arquivos temporários
                        os.unlink(tmp_priv_path)
                        os.unlink(tmp_enc_path)
                        os.unlink(output_path)
                    except ValueError as e:
                        error_msg = str(e)
                        if "password" in error_msg.lower() or "incorrect" in error_msg.lower() or "bad decrypt" in error_msg.lower():
                            st.error(f"Erro: A senha está incorreta ou a chave requer senha. Verifique se digitou a senha correta.")
                        else:
                            st.error(f"Erro ao descriptografar: {error_msg}")
                    except Exception as e:
                        error_msg = str(e)
                        # Verificar se é erro relacionado a senha
                        if "password" in error_msg.lower() or "bad decrypt" in error_msg.lower() or "incorrect" in error_msg.lower():
                            st.error(f"Erro: A chave privada requer senha ou a senha está incorreta. Por favor, verifique a senha.")
                        else:
                            st.error(f"Erro ao descriptografar: {error_msg}")
        
        elif menu == "Gerar Hash":
            st.header("Geração de Hash")
            st.info("Gera o hash SHA-256 de um arquivo. O resultado será salvo em um arquivo .has")
            
            input_file = st.file_uploader("Arquivo para Calcular Hash", type=None)
            algo = st.selectbox("Algoritmo de Hash", ["sha256", "sha512", "sha1", "md5"], index=0)
            
            if st.button("Gerar Hash", type="primary"):
                if not input_file:
                    st.warning("Por favor, faça upload de um arquivo.")
                else:
                    try:
                        # Salvar arquivo temporário
                        with tempfile.NamedTemporaryFile(delete=False) as tmp_input:
                            tmp_input.write(input_file.read())
                            tmp_input_path = tmp_input.name
                        
                        output_path = tmp_input_path + ".has"
                        
                        do_hash(tmp_input_path, output_path, algo)
                        
                        with open(output_path, 'r') as f:
                            hash_data = f.read()
                        
                        st.success("Hash gerado com sucesso!")
                        
                        # Mostrar o hash
                        hash_value = hash_data.strip().split(':')[1] if ':' in hash_data else hash_data.strip()
                        st.code(hash_value, language=None)
                        
                        st.download_button(
                            label="Baixar Arquivo de Hash",
                            data=hash_data,
                            file_name=input_file.name + ".has",
                            mime="text/plain"
                        )
                        
                        # Limpar arquivos temporários
                        os.unlink(tmp_input_path)
                        os.unlink(output_path)
                    except Exception as e:
                        st.error(f"Erro ao gerar hash: {str(e)}")

if __name__ == "__main__":
    main()

