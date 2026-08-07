"""
merge_evtx.py
複数のEVTXファイルを1つのEVTXファイルに結合する。

EVTXファイル構造:
  - ファイルヘッダ (4096 bytes): ElfFile\x00 マジック + チャンク数等 + CRC32
  - チャンク列 (各65536 bytes): ElfChnk\x00 マジック + イベントレコード群

方針:
  - 各ファイルのチャンクをそのまま抽出（内容・CRC32は変更しない）
  - 新しいファイルヘッダを構築してチャンク数とCRC32を更新
  - オリジナルファイルは一切変更しない
"""

import struct
import binascii
import os
import sys

EVTX_FILE_MAGIC   = b'ElfFile\x00'
EVTX_CHUNK_MAGIC  = b'ElfChnk\x00'
FILE_HEADER_SIZE  = 4096
CHUNK_SIZE        = 65536


def compute_crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def read_chunks(filepath: str) -> list[bytes]:
    """EVTXファイルからチャンクを全て読み込む"""
    chunks = []
    with open(filepath, 'rb') as f:
        header = f.read(FILE_HEADER_SIZE)

    if len(header) < FILE_HEADER_SIZE:
        raise ValueError(f"ファイルが小さすぎます: {filepath}")
    if header[:8] != EVTX_FILE_MAGIC:
        raise ValueError(f"EVTXではありません: {filepath}")

    # ヘッダのチャンク数を使う（末尾は未使用の空き領域なので実ファイルサイズより小さい）
    num_chunks = struct.unpack_from('<H', header, 42)[0]

    with open(filepath, 'rb') as f:
        f.seek(FILE_HEADER_SIZE)
        for i in range(num_chunks):
            chunk = f.read(CHUNK_SIZE)
            if len(chunk) != CHUNK_SIZE:
                print(f"  [警告] チャンク{i}が短い({len(chunk)}bytes), スキップ")
                break
            if chunk[:8] != EVTX_CHUNK_MAGIC:
                print(f"  [警告] チャンク{i}のマジックが不正, スキップ")
                continue
            chunks.append(chunk)

    return chunks


def get_last_record_id(chunks: list[bytes]) -> int:
    """全チャンクの中で最大のイベントレコードIDを返す"""
    max_id = 0
    for chunk in chunks:
        # ElfChnk offset 24: EventRecords last record ID (uint64)
        last_id = struct.unpack_from('<Q', chunk, 24)[0]
        if last_id > max_id:
            max_id = last_id
    return max_id


def build_file_header(num_chunks: int, next_record_id: int) -> bytes:
    """EVTXファイルヘッダを構築する (4096 bytes)"""
    header = bytearray(FILE_HEADER_SIZE)

    # Magic
    header[0:8] = EVTX_FILE_MAGIC

    # Oldest chunk number (= 0)
    struct.pack_into('<Q', header, 8, 0)

    # Current chunk number (= last chunk index)
    struct.pack_into('<Q', header, 16, max(0, num_chunks - 1))

    # Next record identifier
    struct.pack_into('<Q', header, 24, next_record_id)

    # Header area byte count = 128
    struct.pack_into('<I', header, 32, 128)

    # Minor version = 1
    struct.pack_into('<H', header, 36, 1)

    # Major version = 3
    struct.pack_into('<H', header, 38, 3)

    # Header block size = 4096
    struct.pack_into('<H', header, 40, FILE_HEADER_SIZE)

    # Number of chunks
    struct.pack_into('<H', header, 42, num_chunks)

    # Flags = 0 (クリーン状態)
    struct.pack_into('<I', header, 120, 0)

    # CRC32 (先頭120バイトに対して計算)
    crc = compute_crc32(bytes(header[:120]))
    struct.pack_into('<I', header, 124, crc)

    return bytes(header)


def merge_evtx(input_files: list[str], output_path: str) -> None:
    all_chunks = []

    for filepath in input_files:
        name = os.path.basename(filepath)
        print(f"読み込み中: {name}")
        try:
            chunks = read_chunks(filepath)
            print(f"  → {len(chunks)} チャンク ({len(chunks) * CHUNK_SIZE // 1024} KB)")
            all_chunks.extend(chunks)
        except Exception as e:
            print(f"  [エラー] {e}, スキップ")

    if not all_chunks:
        print("チャンクが1つも読み込めませんでした。")
        sys.exit(1)

    print(f"\n合計: {len(all_chunks)} チャンク")

    next_record_id = get_last_record_id(all_chunks) + 1
    file_header = build_file_header(len(all_chunks), next_record_id)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print(f"書き込み中: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(file_header)
        for chunk in all_chunks:
            f.write(chunk)

    total_size = os.path.getsize(output_path)
    print(f"完了: {total_size // 1024 // 1024} MB ({output_path})")


if __name__ == '__main__':
    BASE = r"c:\Users\komat\OneDrive\Desktop\ATLAS以外のデータセット"
    EVTX_DIR = os.path.join(BASE, r"apt-persistence\Datasets\C_Data\97\Evtx_Logs")
    OUT_DIR  = os.path.join(BASE, r"analysis_data\C_Data97")
    OUT_FILE = os.path.join(OUT_DIR, "C_Data97_combined.evtx")

    INPUT_FILES = [
        os.path.join(EVTX_DIR, "Security.evtx"),
        os.path.join(EVTX_DIR, "Sysmon.evtx"),
        os.path.join(EVTX_DIR, "TaskScheduler.evtx"),
        os.path.join(EVTX_DIR, "Application.evtx"),
        os.path.join(EVTX_DIR, "System.evtx"),
    ]

    # 存在するファイルのみ
    INPUT_FILES = [f for f in INPUT_FILES if os.path.exists(f)]
    print(f"対象ファイル: {len(INPUT_FILES)} 件")
    for f in INPUT_FILES:
        size_mb = os.path.getsize(f) / 1024 / 1024
        print(f"  {os.path.basename(f)}: {size_mb:.1f} MB")
    print()

    merge_evtx(INPUT_FILES, OUT_FILE)
