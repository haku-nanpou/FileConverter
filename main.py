import os
import hashlib
import lzma
from pathlib import Path
from cryptography.fernet import Fernet
import base64

def derive_key_from_password(password: str) -> bytes:
    """
    パスワードから暗号化キーを生成
    SHA-256でハッシュ化してからBase64でエンコード
    """
    # パスワードをSHA-256でハッシュ化
    key = hashlib.sha256(password.encode('utf-8')).digest()
    # Fernetが要求する形式にエンコード
    return base64.urlsafe_b64encode(key)


def encrypt_file(input_file_path: str, output_folder: str, password: str) -> str:
    """
    ファイルを圧縮してから暗号化
    
    Args:
        input_file_path: 暗号化する元ファイルのパス
        output_folder: 暗号化されたファイルを保存するフォルダ
        password: 暗号化キーとして使用するパスワード
    
    Returns:
        暗号化されたファイルのパス
    """
    # 入力ファイルの存在確認
    if not os.path.exists(input_file_path):
        raise FileNotFoundError(f"ファイルが見つかりません: {input_file_path}")
    
    # 出力フォルダの作成
    os.makedirs(output_folder, exist_ok=True)
    
    # 暗号化キーの生成
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    
    # ファイル名の設定（.compressedを付加）
    input_path = Path(input_file_path)
    output_file_path = os.path.join(output_folder, input_path.name + ".compressed")
    
    # ファイルの読み込み
    with open(input_file_path, 'rb') as file:
        file_data = file.read()
    
    print(f"元のファイルサイズ: {len(file_data):,} bytes")
    
    # データを圧縮
    compressed_data = lzma.compress(file_data, preset=6)
    print(f"圧縮後のサイズ: {len(compressed_data):,} bytes (圧縮率: {(1-len(compressed_data)/len(file_data))*100:.1f}%)")
    
    # 圧縮されたデータを暗号化
    encrypted_data = fernet.encrypt(compressed_data)
    print(f"暗号化後のサイズ: {len(encrypted_data):,} bytes")
    
    # 暗号化されたデータの保存
    with open(output_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)
    
    print(f"ファイルが圧縮・暗号化されました: {output_file_path}")
    return output_file_path


def decrypt_file(input_file_path: str, output_folder: str, password: str) -> str:
    """
    ファイルを復号化してから解凍
    
    Args:
        input_file_path: 復号化する暗号化ファイルのパス
        output_folder: 復号化されたファイルを保存するフォルダ
        password: 復号化キーとして使用するパスワード
    
    Returns:
        復号化されたファイルのパス
    """
    # 入力ファイルの存在確認
    if not os.path.exists(input_file_path):
        raise FileNotFoundError(f"ファイルが見つかりません: {input_file_path}")
    
    # 出力フォルダの作成
    os.makedirs(output_folder, exist_ok=True)
    
    # 復号化キーの生成
    key = derive_key_from_password(password)
    fernet = Fernet(key)
    
    # ファイル名の設定（.compressedを除去）
    input_path = Path(input_file_path)
    original_name = input_path.name.replace('.compressed', '')
    output_file_path = os.path.join(output_folder, original_name)
    
    try:
        # ファイルの読み込みと復号化
        with open(input_file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()
        
        print(f"暗号化ファイルのサイズ: {len(encrypted_data):,} bytes")
        
        # データを復号化
        compressed_data = fernet.decrypt(encrypted_data)
        print(f"復号化後のサイズ: {len(compressed_data):,} bytes")
        
        # データを解凍
        decrypted_data = lzma.decompress(compressed_data)
        print(f"解凍後のサイズ: {len(decrypted_data):,} bytes")
        
        # 復号化・解凍されたデータの保存
        with open(output_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        
        print(f"ファイルが復号化・解凍されました: {output_file_path}")
        return output_file_path
    
    except Exception as e:
        print(f"復号化に失敗しました。パスワードが間違っているか、ファイルが破損している可能性があります: {e}")
        raise


def main():
    """
    メイン関数 - ユーザーインターフェース
    """
    print("=== ファイル暗号化・復号化ツール ===")
    print("1. ファイルを暗号化")
    print("2. ファイルを復号化")
    print("3. 終了")
    
    while True:
        choice = input("\n選択してください (1-3): ").strip()
        
        if choice == '1':
            # 暗号化
            input_file = input("暗号化するファイルのパスを入力: ").strip()
            output_folder = input("出力先フォルダのパスを入力: ").strip()
            password = input("パスワードを入力: ").strip()
            
            try:
                encrypt_file(input_file, output_folder, password)
            except Exception as e:
                print(f"エラー: {e}")
        
        elif choice == '2':
            # 復号化
            input_file = input("復号化するファイルのパスを入力: ").strip()
            output_folder = input("出力先フォルダのパスを入力: ").strip()
            password = input("パスワードを入力: ").strip()
            
            try:
                decrypt_file(input_file, output_folder, password)
            except Exception as e:
                print(f"エラー: {e}")
        
        elif choice == '3':
            print("プログラムを終了します。")
            break
        
        else:
            print("無効な選択です。1-3の中から選択してください。")


if __name__ == "__main__":
    main()
