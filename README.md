
# NVD to OpenCTI STIX Converter / NVD → OpenCTI STIX変換ツール

This Python tool converts NVD CVE JSON data into STIX 2.1 format for OpenCTI.  
It provides comprehensive support for vulnerability enrichment, ensuring smooth integration with OpenCTI environments.

このPythonツールは、NVDのCVE JSONデータをOpenCTI用のSTIX 2.1形式に変換します。  
脆弱性データの拡張処理を行い、OpenCTI環境へのシームレスな統合を支援します。

## ✨ Features / 主な機能

- Supports CVSSv3; falls back to CVSSv2 when CVSSv3 is unavailable  
  CVSSv3に対応し、CVSSv3がない場合はCVSSv2にフォールバックします。
- Extracts product, version, and type (OS/App/Hardware) from CPE  
  CPEから製品名、バージョン、種別（OS/アプリ/ハードウェア）を抽出します。
- Registers vendor as an organization entity linked to software  
  ベンダーを組織エンティティとして登録し、ソフトウェアと関連付けます。
- Normalizes external references (uses domain name or original name)  
  external referencesを正規化し、ドメイン名または元の名前を使用します。
- Adds tags to external reference names if available  
  external referencesにタグを付与します。
- Checks against CISA Known Exploited Vulnerabilities (KEV)  
  CISA Known Exploited Vulnerabilities（KEV）との突合を行います。
- Enriches data with EPSS scores  
  EPSSスコアを付与します。
- Continues processing even if CISA/EPSS files are missing  
  CISA/EPSSファイルがなくても処理を継続します。

## 📦 Requirements / 必要なパッケージ

    Install all required packages:

    pip install -r requirements.txt


## 🔧 Usage / 使い方

    Basic usage:

        python convert\_nvd\_to\_opencti.py \<nvd\_json\_file>

    Example:

        python convert\_nvd\_to\_opencti.py nvdcve-1.1-modified.json



## 📁 Input files / 入力ファイル

- Main:
  - NVD JSON file (e.g., `nvdcve-1.1-modified.json`)
- Optional:
  - `cisa_known_exploited_vulnerabilities.json`
  - `epss_scores-current.csv.gz`

## 📤 Output file / 出力ファイル

- `output_opencti_stix.json`

## 🛡 License / ライセンス

MIT License

