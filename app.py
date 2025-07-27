import streamlit as st
from chacha20_crypto import (
    generate_key_nonce,
    encrypt_chacha20,
    decrypt_chacha20,
    base64_encode,
    base64_decode
)

def main():
    st.title("🔐 ChaCha20 Encryption & Decryption Demo")
    st.markdown("Encrypt or decrypt messages and files using the ChaCha20 stream cipher.")

    if st.button("🔁 Generate Key & Nonce"):
        key, nonce = generate_key_nonce()
        st.session_state['key'] = base64_encode(key)
        st.session_state['nonce'] = base64_encode(nonce)

    key_b64 = st.text_input("🔑 Base64 Key", value=st.session_state.get("key", ""))
    nonce_b64 = st.text_input("📛 Base64 Nonce", value=st.session_state.get("nonce", ""))

    if not key_b64 or not nonce_b64:
        st.warning("Provide valid base64-encoded key and nonce.")
        return

    try:
        key = base64_decode(key_b64)
        nonce = base64_decode(nonce_b64)
    except Exception as e:
        st.error(f"Invalid base64 key/nonce: {e}")
        return

    mode = st.radio("Select Operation", ["Encrypt", "Decrypt"])

    # Text Mode
    with st.expander("📩 Text Encryption/Decryption"):
        text = st.text_area("Enter your text (plaintext or base64 ciphertext):", "")
        if st.button(f"{mode} Text"):
            try:
                if not text:
                    st.warning("Please enter some text.")
                else:
                    if mode == "Encrypt":
                        encrypted_bytes = encrypt_chacha20(key, nonce, text.encode())
                        st.text_area("Encrypted Output (base64):", base64_encode(encrypted_bytes))
                    else:
                        # Decode base64 before decryption
                        decrypted_bytes = decrypt_chacha20(key, nonce, base64_decode(text))
                        st.text_area("Decrypted Output (UTF-8):", decrypted_bytes.decode('utf-8'))
            except Exception as e:
                st.error(f"{mode}ion failed: {e}")

    # File Mode
    with st.expander("📂 File Encryption/Decryption"):
        uploaded_file = st.file_uploader("Upload a file")
        if uploaded_file and st.button(f"{mode} File"):
            try:
                file_bytes = uploaded_file.read()
                result = encrypt_chacha20(key, nonce, file_bytes) if mode == "Encrypt" else decrypt_chacha20(key, nonce, file_bytes)
                file_ext = ".enc" if mode == "Encrypt" else ".dec"
                st.download_button(f"Download Result", result, file_name=uploaded_file.name + file_ext)
            except Exception as e:
                st.error(f"File {mode.lower()}ion failed: {e}")

main()
