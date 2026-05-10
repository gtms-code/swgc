# SWGC — Secure WireGuard Client

Windows向けのセキュアなWireGuardクライアントです。[Tauri v2](https://tauri.app/) + Rust + React で実装されており、秘密鍵をディスクに平文で保存しないことを最大の特徴としています。

## 特徴

- **秘密鍵の平文保存なし** — 秘密鍵は [Windows DPAPI](https://learn.microsoft.com/ja-jp/windows/win32/api/dpapi/) で暗号化してレジストリに保存されます
- **メモリ内処理** — 接続時、秘密鍵はRustのヒープ上で復号されてカーネルドライバーに渡すのみ。設定ファイルへの書き出しは行いません
- **wireguard-nt利用** — [wireguard-nt](https://git.zx2c4.com/wireguard-nt) のカーネルモードドライバーを直接呼び出すことで、WireGuard for Windowsのサービスに依存しません
- **自動再接続** — セッションが期限切れになると自動的に再接続を試みます（ユーザーが「切断」ボタンを押した場合を除く）
- **セッション監視UI** — ハンドシェイクの経過時間・送受信バイト数をリアルタイム表示。セッションが古くなると警告を表示します

## スクリーンショット

> 接続中の状態 (ハンドシェイク・TX/RX表示)

## 必要環境

| 項目 | 要件 |
|---|---|
| OS | Windows 10 21H1 以降 (x64) |
| 権限 | 管理者権限 (wireguard.sys のインストールに必要) |
| ランタイム | Microsoft Visual C++ 再頒布可能パッケージ 2022 |

> **注意**: ビルド済みの `wireguard.dll` (wireguard-nt 1.0) を同梱しています。このDLLが `wireguard.sys` カーネルドライバーを自動的にインストール・管理します。

## 使い方

1. リリースページから `swgc_x.x.x_x64-setup.exe` をダウンロードしてインストール
2. 管理者として起動
3. **「設定をインポート (.conf)」** ボタンから WireGuard 設定ファイル (`.conf`) を選択
4. **「接続」** ボタンをクリック
5. ハンドシェイクが確立されると接続時間・TX/RXが表示されます

## ビルド方法

### 前提条件

- [Rust](https://rustup.rs/) (stable)
- [Node.js](https://nodejs.org/) 18以上
- [Tauri CLI](https://tauri.app/start/prerequisites/)

```powershell
# 依存関係インストール
npm install

# 開発モードで起動 (管理者権限のターミナルで実行)
npm run tauri dev

# リリースビルド
npm run tauri build
```

> `src-tauri/wireguard.dll` は wireguard-nt のビルド済みバイナリです。ビルド時はそのまま利用されます。独自にビルドする場合は [wireguard-nt](https://git.zx2c4.com/wireguard-nt) を参照してください。

## アーキテクチャ

```
src/                    # React フロントエンド (TypeScript)
  App.tsx               # メインUI・ステータス表示・自動再接続検出
  commands.ts           # Tauri IPC ラッパー
src-tauri/src/          # Rust バックエンド
  wireguard.rs          # WireGuard tunnel管理・監視スレッド・自動再接続
  wg_nt.rs              # wireguard-nt FFI バインディング
  config.rs             # 設定ファイルのパース・DPAPI暗号化
  crypto.rs             # DPAPI ラッパー
  commands.rs           # Tauri コマンドハンドラー
src-tauri/
  wireguard.dll         # wireguard-nt 1.0 (GPLv2, WireGuard LLC)
```

### セキュリティ設計

```
.conf ファイル
    ↓ parse
WgConfig (ヒープ上、ZeroizeOnDrop)
    ↓ DPAPI暗号化
レジストリ (HKCU\...\SWGC)
    ↓ 接続時にDPAPI復号
WgConfig (ヒープ上)
    ↓ WireGuardSetConfiguration
wireguard.sys (カーネル)
    ↓ ZeroizeOnDrop で上書きゼロ化
```

## 免責事項

このソフトウェアは個人利用・学習目的で作成されました。本番環境での利用は自己責任でお願いします。

## ライセンス

本プロジェクト (ソースコード・同梱の `wireguard.dll` を含む全体): **GNU General Public License v2.0**

`wireguard.dll` は [wireguard-nt](https://git.zx2c4.com/wireguard-nt) のビルド済みバイナリです (Copyright © WireGuard LLC, GPLv2)。wireguard-nt が GPLv2 only のため、本プロジェクト全体も GPLv2 で頒布しています。
