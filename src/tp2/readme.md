# TP2 - Shellcode Analyzer

## Installation

```bash
pip install -r requirements_tp2.txt
```

## Utilisation

```bash
python main.py -f shellcode_easy.txt -o rapport_easy.pdf
python main.py --all
```

## Options

- `-f` : fichier contenant le shellcode
- `-s` : shellcode en hex direct
- `-o` : fichier PDF de sortie
- `--all` : analyser les 3 shellcodes et generer les 3 PDF
